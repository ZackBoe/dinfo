/*
Copyright © 2019 Zack Boehm <git@zackboehm.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
  "fmt"
  "os"
  "errors"
  "time"
  "strings"
  "net"
  "crypto/tls"
  // "net/url"
  "strconv"
  "github.com/spf13/cobra"
  
  "github.com/araddon/dateparse"

  . "github.com/logrusorgru/aurora"

  "github.com/goware/urlx"
  "github.com/weppos/publicsuffix-go/publicsuffix"

  // "github.com/miekg/dns" // Might check google/cf against local resolver?

  "github.com/ipinfo/go-ipinfo/ipinfo"

  // "github.com/domainr/whois"
  "github.com/likexian/whois-go"
  "github.com/likexian/whois-parser-go"
)


var cfgFile string
var FlagIP bool
var FlagCert bool
var FlagWhois bool

// thx https://stackoverflow.com/a/50825191/1810897
// pls give https://github.com/golang/go/issues/29146
var privateIPBlocks []*net.IPNet

var pad = "%-12s%s\n"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
  Use:   "dinfo [domain]",
  Short: "Provides brief information about a domain",
  Long: `Provides brief information about a provided domain or list of domains,
optionally including certificate and whois data.

You can include multiple domains or pipe into dinfo via xargs:
cat list.txt | xargs dinfo

Will only provide basic information on the first returned IP
and first returned nameserver from WHOIS lookup.
Will not display more than 6 cert SANs

Uses IPInfo.io for IP lookup data. Currently does not supply
an API key, so may be severely rate limited.

https://github.com/zackboe/dinfo`,
  Args: func(cmd *cobra.Command, args []string) error {
    if len(args) < 1 {
      return errors.New("requires domain argument")
    }
    return nil
  },
  Run: func(cmd *cobra.Command, args []string) {

    for index, url := range args {
    
    u, err := urlx.Parse(url)
    host, _, _ := urlx.SplitHostPort(u)
    domain, err := publicsuffix.Domain(host)
    
    // fmt.Println("Hello World! ["+ host +"] ["+ domain +"]")

    if len(domain) <= 0 {
      fmt.Println(Red("Could not parse domain name from "+host))
      os.Exit(1)
    }

    if (!FlagIP) {

      ip, err := net.LookupIP(host)

      if ip != nil && !isPrivateIP(ip[0]) {

      ipinfoAuthTransport := ipinfo.AuthTransport{}
      ipinfoHttpClient := ipinfoAuthTransport.Client()
      ipinfoClient := ipinfo.NewClient(ipinfoHttpClient)
      ipDetails, err := ipinfoClient.GetInfo(ip[0])

      fmt.Println(BgBlack(Bold(White("IP details for "+host))))
      fmt.Printf(pad, "IP:", Cyan(ip[0]))
      fmt.Printf(pad, "Hostname:", Cyan(ipDetails.Hostname))
      fmt.Printf(pad, "Location:", Cyan("["+ipDetails.Country+"] "+ipDetails.City+", "+ipDetails.Region))
      fmt.Printf(pad, "ASN:", Cyan(ipDetails.Organization))
      fmt.Printf(pad, "More:", Cyan("https://ipinfo.io/"+ip[0].String()))
      
      if err != nil {
        panic(err)
      }

      } else if isPrivateIP(ip[0])  {
        fmt.Println(Red("Not performing IP lookup for private IP "+ip[0].String()))
      }

      if err != nil {
        panic(err)
      }
    }
    
    if(FlagCert) {
      conn, conErr := tls.Dial("tcp", host+":443", &tls.Config{
        // InsecureSkipVerify: true,
      })
      if conErr != nil {
        fmt.Println(Red("Could not connect to "+host+":443"))
        fmt.Println(Red(conErr.Error()))
      } else {

        certErr := conn.VerifyHostname(host)
        cert := conn.ConnectionState().PeerCertificates[0]

        if !FlagIP {
          fmt.Println()
        }
        if certErr != nil {
          fmt.Println(BgBlack(Bold(Red("Invalid cert details for "+host))))
          fmt.Println(certErr)
        } else {
          fmt.Println(BgBlack(Bold(White("Cert details for "+host))))
        }
        fmt.Printf(pad, "Cert CA:", Cyan("[" + cert.Issuer.Country[0] + "] " + cert.Issuer.Organization[0]))
        fmt.Printf(pad, "Cert CN:", Cyan(cert.Subject.CommonName))
        fmt.Printf(pad, "Cert Valid:", Cyan(format3339(cert.NotBefore.String(), true) + " - " + format3339(cert.NotAfter.String(), true)))
        if len(cert.DNSNames) < 6 {
          fmt.Printf(pad, "Cert SANs:", Cyan(strings.Join(cert.DNSNames, ", ")))
        } else {
          fmt.Printf(pad, "Cert SANs:", Cyan(strconv.Itoa(len(cert.DNSNames))))
        }
        fmt.Printf(pad, "More:", Cyan("https://www.ssllabs.com/ssltest/analyze.html?d=" + host + "&hideResults=on"))
      }
    }

    if(FlagWhois) {
      // request, err := whois.NewRequest(domain)
      // response, err := whois.DefaultClient.Fetch(request)
      response, err := whois.Whois(domain)
      whoisData, err := whoisparser.Parse(response)

      if len(whoisData.Domain.Domain) > 0 {

        fmt.Println()
        fmt.Println(BgBlack(Bold(White("WHOIS lookup for "+strings.ToLower(whoisData.Domain.Domain)))))
        fmt.Printf(pad, "Registrar:", Cyan(whoisData.Registrar.Name + " ("+ whoisData.Registrar.ReferralURL +")"))
        fmt.Printf(pad, "Reg Dates:", Cyan("C:"+ format3339(whoisData.Domain.CreatedDate, false) + " U:" + format3339(whoisData.Domain.UpdatedDate, false) + " E:" + format3339(whoisData.Domain.ExpirationDate, false)))
        fmt.Printf(pad, "Nameserver:", Cyan(strings.Split(whoisData.Domain.NameServers, ",")[0]))
        fmt.Printf(pad, "More:", Cyan("https://whois.icann.org/en/lookup?name="+strings.ToLower(whoisData.Domain.Domain)))

      }

      if err != nil {
        if err == whoisparser.ErrDomainNotFound || err == whoisparser.ErrDomainInvalidData {
          fmt.Println(Red("WHOIS lookup failed for "+domain+": "+err.Error()))
        } else {
          panic(err)
        }
      }
    }
    
    if err != nil {
      if err == err.(*net.DNSError) {
        fmt.Println(Red("IP lookup for failed for "+host))
      } else {
        panic(err)
      }
    }

    if index != len(args) - 1 {
      fmt.Println()
    }
  }
  },
}

func format3339(D string, includeTime bool) string {
  t, err := dateparse.ParseAny(D)
  // parsed, err := time.Parse(time.RFC3339, t)
  if err != nil {
    // Return given date string when unable to parse.
    // Some registries provide create strings like "before Aug-1996"
    return D
  }
  if includeTime {
    return t.In(time.Now().Location()).Format("2006-01-02 15:04 MST")
  } else {
    return t.In(time.Now().Location()).Format("2006-01-02")
  }
}

func Execute() {
  if err := rootCmd.Execute(); err != nil {
    fmt.Println(err)
    os.Exit(1)
  }
}

func isPrivateIP(ip net.IP) bool {
  if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
    return true
  }

  for _, block := range privateIPBlocks {
    if block.Contains(ip) {
      return true
    }
  }
  return false
}

func init() {
  rootCmd.PersistentFlags().BoolVarP(&FlagIP, "skip-ip", "i", false, "Skip IP Lookup")
  rootCmd.PersistentFlags().BoolVarP(&FlagCert, "cert", "c", false, "Perform TLS certificate check")
  rootCmd.PersistentFlags().BoolVarP(&FlagWhois, "whois", "w", false, "Perform WHOIS lookup")

  for _, cidr := range []string{
    "127.0.0.0/8",    // IPv4 loopback
    "10.0.0.0/8",     // RFC1918
    "172.16.0.0/12",  // RFC1918
    "192.168.0.0/16", // RFC1918
    "169.254.0.0/16", // RFC3927 link-local
    "::1/128",        // IPv6 loopback
    "fe80::/10",      // IPv6 link-local
    "fc00::/7",       // IPv6 unique local addr
  } {
    _, block, err := net.ParseCIDR(cidr)
    if err != nil {
      panic(fmt.Errorf("parse error on %q: %v", cidr, err))
    }
    privateIPBlocks = append(privateIPBlocks, block)
  }

}

