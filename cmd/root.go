// Copyright © 2016 Kevin Kirsche <kevin.kirsche@verizon.com> <kev.kirsche@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyz"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var (
	timeout   int
	verbose   bool
	dnsServer string
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "dnsenum",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		// wildcards := RandString(11)

		for _, domain := range args {
			if verbose {
				logrus.WithField("domain", domain).Info("Looking up domain...")
			}

			c := new(dns.Client)
			// CONFIGURE THE CLIENT ##################################################
			timeoutStr := strconv.Itoa(timeout)
			timeoutDur, err := time.ParseDuration(fmt.Sprintf("%ss", timeoutStr))
			if err != nil {
				logrus.WithField("error", err).Errorln("Error received when parsing timeout")
				return
			}
			c.DialTimeout = timeoutDur
			c.ReadTimeout = timeoutDur
			c.WriteTimeout = timeoutDur

			// RETRIEVE A RECORDS ####################################################
			addrs, rtt, err := retrieveARecord(c, domain)
			if err != nil {
				logrus.WithField("error", err).Errorln("Error received when retrieving A Record")
			}
			logrus.WithField("rtt", rtt).Info("A Record query completed in")
			for _, addr := range addrs {
				logrus.WithField("ip", addr).Info("Found IP Address")
			}

			// RETRIEVE NS RECORDS ###################################################
			addrs, rtt, err = retrieveNSRecord(c, domain)
			if err != nil {
				logrus.WithField("error", err).Errorln("Error received when retrieving NS Record")
			}
			logrus.WithField("rtt", rtt).Info("NS Record query completed in")
			for _, addr := range addrs {
				logrus.WithField("ip", addr).Info("Found Name Server")
			}

			// RETRIEVE MX RECORDS ###################################################
			addrs, rtt, err = retrieveMXRecord(c, domain)
			if err != nil {
				logrus.WithField("error", err).Errorln("Error received when retrieving NS Record")
			}
			logrus.WithField("rtt", rtt).Info("MX Record query completed in")
			for _, addr := range addrs {
				logrus.WithField("ip", addr).Info("Found MX CNAME")
			}

			// ZONE TRANSFER #########################################################
			addrs, rtt, err = zoneTransferTest(c, domain)
			if err != nil {
				logrus.WithField("error", err).Errorln("Error received when retrieving NS Record")
			}
			logrus.WithField("rtt", rtt).Info("Zone Transfer (AXFR) query completed in")
			for _, addr := range addrs {
				logrus.WithField("ip", addr).Info("Found AXFR")
			}
		}
	},
}

func retrieveARecord(c *dns.Client, domain string) ([]string, time.Duration, error) {
	ipv4m := new(dns.Msg)
	ipv4m.Id = dns.Id()
	ipv4m.RecursionDesired = true
	ipv4m.Question = make([]dns.Question, 1)
	ipv4m.Question[0] = dns.Question{Name: dns.Fqdn(domain), Qtype: dns.TypeA, Qclass: dns.ClassANY}

	dnsServerPort := net.JoinHostPort(dnsServer, "53")

	in, rtt, err := c.Exchange(ipv4m, dnsServerPort)
	if err != nil {
		dur, _ := time.ParseDuration("0s")
		return []string{}, dur, err
	}

	var addrs []string
	for _, answer := range in.Answer {
		splitAnswer := strings.Split(answer.String(), "\t")
		for _, answerField := range splitAnswer {
			if net.ParseIP(answerField) == nil {
				continue
			}
			addrs = append(addrs, answerField)
		}
	}

	return addrs, rtt, nil
}

func retrieveNSRecord(c *dns.Client, domain string) ([]string, time.Duration, error) {
	nsm := new(dns.Msg)
	nsm.Id = dns.Id()
	nsm.RecursionDesired = true
	nsm.Question = make([]dns.Question, 1)
	nsm.Question[0] = dns.Question{Name: dns.Fqdn(domain), Qtype: dns.TypeNS, Qclass: dns.ClassANY}

	dnsServerPort := net.JoinHostPort(dnsServer, "53")

	in, rtt, err := c.Exchange(nsm, dnsServerPort)
	if err != nil {
		dur, _ := time.ParseDuration("0s")
		return []string{}, dur, err
	}

	var nss []string
	for _, answer := range in.Ns {
		splitAnswer := strings.Split(answer.String(), "\t")
		for i, answerField := range splitAnswer {
			if i%4 == 0 && i != 0 {
				fields := strings.Split(answerField, " ")
				for i, field := range fields {
					if i == 0 || i == 1 {
						nss = append(nss, field)
					}
				}
			}
		}
	}

	return nss, rtt, nil
}

func retrieveMXRecord(c *dns.Client, domain string) ([]string, time.Duration, error) {
	nsm := new(dns.Msg)
	nsm.Id = dns.Id()
	nsm.RecursionDesired = true
	nsm.Question = make([]dns.Question, 1)
	nsm.Question[0] = dns.Question{Name: dns.Fqdn(domain), Qtype: dns.TypeMX, Qclass: dns.ClassANY}

	dnsServerPort := net.JoinHostPort(dnsServer, "53")

	in, rtt, err := c.Exchange(nsm, dnsServerPort)
	if err != nil {
		dur, _ := time.ParseDuration("0s")
		return []string{}, dur, err
	}

	var mxs []string
	for _, answer := range in.Answer {
		splitAnswer := strings.Split(answer.String(), "\t")
		for i, answerField := range splitAnswer {
			if i%4 == 0 && i != 0 {
				mxs = append(mxs, answerField)
			}
		}
	}

	return mxs, rtt, nil
}

func zoneTransferTest(c *dns.Client, domain string) ([]string, time.Duration, error) {
	nsm := new(dns.Msg)
	nsm.Id = dns.Id()
	nsm.RecursionDesired = true
	nsm.Question = make([]dns.Question, 1)
	nsm.Question[0] = dns.Question{Name: dns.Fqdn(domain), Qtype: dns.TypeAXFR, Qclass: dns.ClassANY}

	dnsServerPort := net.JoinHostPort(dnsServer, "53")

	in, rtt, err := c.Exchange(nsm, dnsServerPort)
	if err != nil {
		dur, _ := time.ParseDuration("0s")
		return []string{}, dur, err
	}

	var zones []string
	for _, answer := range in.Answer {
		splitAnswer := strings.Split(answer.String(), "\t")
		for i, answerField := range splitAnswer {
			if i%4 == 0 && i != 0 {
				zones = append(zones, answerField)
			}
		}
	}

	return zones, rtt, nil
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	RootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 10, "The TCP and UDP timeout values in seconds (default: 10s).")
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Be verbose: show all the progress and all the error messages.")

	// DNS Server to query
	RootCmd.PersistentFlags().StringVarP(&dnsServer, "dns-server", "s", "166.37.162.103", "Use this DNS server for A, NS and MX queries.")
}
