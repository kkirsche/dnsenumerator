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

// DNSResult is the individual lines of a DNS answer section
type DNSResult struct {
	Name       string
	TTLSec     string
	Class      string
	Type       string
	IP         string
	Preference string
}

var afterFirst bool

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

			retrieveDomainInformation(c, domain)
		}
	},
}

func retrieveDomainInformation(c *dns.Client, domain string) {
	if afterFirst {
		fmt.Println()
	}
	afterFirst = true

	logrus.WithField("domain", domain).Info("Looking up domain...")
	// RETRIEVE ANY RECORDS ##################################################
	dnsResults, rtt, err := retrieveANYRecord(c, domain)
	if err != nil {
		logrus.WithField("error", err).Errorln("Error received when retrieving A Record")
	}
	logrus.WithField("rtt", rtt).Info("ANY Record query completed in")

	// PRINT RESULTS OF ANY QUERY ############################################
	var additionalDomains []string
	if len(dnsResults) == 0 {
		logrus.WithField("domain", domain).Errorln("No results found for domain")
	} else {
		for _, result := range dnsResults {
			if result.Type != "MX" {
				logrus.WithFields(logrus.Fields{
					"ip":    result.IP,
					"type":  result.Type,
					"ttl":   result.TTLSec,
					"class": result.Class,
				}).Infoln(fmt.Sprintf("Found %s record", result.Type))
			} else {
				logrus.WithFields(logrus.Fields{
					"ip":         result.IP,
					"type":       result.Type,
					"ttl":        result.TTLSec,
					"preference": result.Preference,
					"class":      result.Class,
				}).Infoln(fmt.Sprintf("Found %s record", result.Type))
			}
			ip := net.ParseIP(result.IP)
			if ip == nil {
				additionalDomains = append(additionalDomains, result.IP)
			}
		}
	}

	// ZONE TRANSFER #########################################################
	zones, rtt, err := zoneTransferTest(c, domain)
	if err != nil {
		logrus.WithField("error", err).Errorln("Error received when retrieving NS Record")
	}
	logrus.WithField("rtt", rtt).Infoln("Zone Transfer (AXFR) query completed in")
	if len(zones) == 0 {
		logrus.WithField("domain", domain).Errorln("No Zone Transfer allowed for domain")
	} else {
		for _, zone := range zones {
			logrus.WithField("ip", zone).Infoln("Found AXFR")
		}
	}
	for _, aDom := range additionalDomains {
		retrieveDomainInformation(c, aDom)
	}
}

func retrieveANYRecord(c *dns.Client, domain string) ([]DNSResult, time.Duration, error) {
	ipv4m := new(dns.Msg)
	ipv4m.Id = dns.Id()
	ipv4m.RecursionDesired = true
	ipv4m.Question = make([]dns.Question, 1)
	ipv4m.Question[0] = dns.Question{Name: dns.Fqdn(domain), Qtype: dns.TypeANY, Qclass: dns.ClassANY}

	dnsServerPort := net.JoinHostPort(dnsServer, "53")

	in, rtt, err := c.Exchange(ipv4m, dnsServerPort)
	if err != nil {
		dur, _ := time.ParseDuration("0s")
		return []DNSResult{}, dur, err
	}

	var results []DNSResult
	for _, answer := range in.Answer {
		lines := strings.Split(answer.String(), "\n")
		for _, line := range lines {
			splitLine := strings.Split(line, "\t")
			var preferenceAndIP []string
			if splitLine[3] == "MX" {
				preferenceAndIP = strings.Split(splitLine[4], " ")

			}
			result := DNSResult{
				Name:   splitLine[0],
				TTLSec: splitLine[1],
				Class:  splitLine[2],
				Type:   splitLine[3],
				IP:     splitLine[4],
			}

			if result.Type == "MX" {
				result.IP = preferenceAndIP[1]
				result.Preference = preferenceAndIP[0]
			}
			results = append(results, result)
		}
	}

	return results, rtt, nil
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
