// Copyright © 2018 Joel Rebello <joel.rebello@booking.com>
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
	"io/ioutil"
	"log/syslog"
	"os"

	"github.com/sirupsen/logrus"
	logrusSyslog "github.com/sirupsen/logrus/hooks/syslog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	logger  *logrus.Logger
	debug   bool
	output  bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:              "bmcldap",
	Short:            "A ldap server, proxy to LDAP authenticate, authorize BMC user accounts",
	TraverseChildren: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		setupLogger()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func setupLogger() {
	logger = logrus.New()

	if output {
		logger.Out = os.Stdout
	} else {
		logger.SetOutput(ioutil.Discard)
	}

	hook, err := logrusSyslog.NewSyslogHook("", "", syslog.LOG_INFO, "bmcldap")
	if err != nil {
		logger.Error("Unable to connect to local syslog daemon.")
	} else {
		logger.AddHook(hook)
	}

	if debug {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
}

func init() {
	var home = os.Getenv("HOME")
	cfgFile = fmt.Sprintf("%s/.bmcldap.yml", home)

	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
	rootCmd.PersistentFlags().BoolVarP(&output, "output", "o", false, "Enable logging on STDOUT. Otherwise, it's only on SysLog.")
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", cfgFile, "Configuration file for bmcldap.")
	cobra.OnInitialize(initConfig)
}

func initConfig() {
	viper.SetConfigFile(cfgFile)
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("Error reading config: ", err)
		os.Exit(1)
	}
}
