/*
 * Copyright 2015 Zoho Corporation Private Limited
 *
 * Licensed under Go Lang SNMP API License Terms (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * WebNMS/SNMPAPI/LICENSE_AGREEMENT.doc
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package parser2

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"webnms/snmp/consts"
)

//Declare the required variable for parsing
//Flags - Optional Params
var Debug bool
var Version consts.Version
var versionStr string
var Community string
var Port int
var Timeout int
var Retries int

//For SNMPv3
var UserName string
var ContextName string
var AuthProtocol consts.AuthProtocol
var authProtocol string
var AuthPassword string
var PrivProtocol consts.PrivProtocol
var privProtocol string
var PrivPassword string
var EngineID []byte
var engineIDStr string
var DriverName string
var DataSrcName string
var dbName string
var DialectID int = -1

//To store the remaining mandatory params
var RemArgs []string

//Get called everytime we run the example program
func init() {
	//Parser command line arguments
	flag.BoolVar(&Debug, "d", false, "Debug Flag: bool")
	flag.StringVar(&versionStr, "v", "v1", "SNMP Version: string")
	flag.StringVar(&Community, "c", "public", "SNMP Community: string")
	flag.IntVar(&Port, "p", 0, "Remote Port: int")
	flag.IntVar(&Timeout, "t", 0, "Timeout: int")
	flag.IntVar(&Retries, "r", 0, "Retries: int")
	//SNMPv3 specific flags
	flag.StringVar(&UserName, "u", "", "USM UserName for SNMPv3")
	flag.StringVar(&ContextName, "n", "", "Context Name")
	flag.StringVar(&authProtocol, "a", "", "USM Authentication Protocol (MD5/SHA)")
	flag.StringVar(&AuthPassword, "w", "", "USM Authentication Password")
	flag.StringVar(&privProtocol, "pp", "", "USM Privacy Protocol (DES/3DES/AES-128/AES-192/AES-256)")
	flag.StringVar(&PrivPassword, "s", "", "USM Privacy Password")
	flag.StringVar(&engineIDStr, "e", "", "Remote Entity's SnmpEngineID for v3")
	flag.Parse()

	RemArgs = flag.Args()
}

func ValidateFlags() error {
	if versionStr == "v1" {
		Version = consts.Version1
	} else if versionStr == "v2" {
		Version = consts.Version2C
	} else if versionStr == "v3" {
		Version = consts.Version3
	} else {
		fmt.Fprint(os.Stderr, "Invalid SNMP version specified. Defaulting to SNMPv1.\n")
	}

	//Perform validation for SNMPv3
	if Version == consts.Version3 {

		if !strings.EqualFold(UserName, "") {

			//Authentication Params
			if !strings.EqualFold(authProtocol, "") {

				if strings.EqualFold(AuthPassword, "") {
					return errors.New("AuthPassword is missing.")
				}
				if strings.EqualFold(authProtocol, "MD5") {
					AuthProtocol = consts.MD5_AUTH
				} else if strings.EqualFold(authProtocol, "SHA") {
					AuthProtocol = consts.SHA_AUTH
				} else {
					return errors.New("Invalid Authentication Protocol: " + authProtocol)
				}

				//Privacy Params
				if !strings.EqualFold(privProtocol, "") {
					if strings.EqualFold(PrivPassword, "") {
						return errors.New("PrivPassword is missing.")
					}

					if strings.EqualFold(privProtocol, "DES") {
						PrivProtocol = consts.DES_PRIV
					} else if strings.EqualFold(privProtocol, "3DES") {
						PrivProtocol = consts.TRIPLE_DES_PRIV
					} else if strings.EqualFold(privProtocol, "AES-128") {
						PrivProtocol = consts.AES_128_PRIV
					} else if strings.EqualFold(privProtocol, "AES-192") {
						PrivProtocol = consts.AES_192_PRIV
					} else if strings.EqualFold(privProtocol, "AES-256") {
						PrivProtocol = consts.AES_256_PRIV
					} else {
						return errors.New("Invalid Privacy Protocol: " + privProtocol)
					}
				}
			} else if (!strings.EqualFold(AuthPassword, "")) ||
				(!strings.EqualFold(privProtocol, "")) ||
				(!strings.EqualFold(PrivPassword, "")) {
				return errors.New("Invalid V3 params provided. Requires authentication protocol/password.")
			}
		} else {
			return errors.New("UserName is missing.")
		}

		if engineIDStr == "" {
			EngineID = nil
		} else {
			//EngineID validation can be done here
			if strings.HasPrefix(engineIDStr, "0x") { //Hex
				var err error
				EngineID, err = hex.DecodeString(strings.TrimPrefix(engineIDStr, "0x"))
				if err != nil {
					return fmt.Errorf("Invalid EngineID provided: %s. Error: %s.", engineIDStr, err.Error())
				}
			} else {
				EngineID = []byte(engineIDStr)
			}
		}

		if strings.TrimSpace(DataSrcName) != "" {
			DataSrcName = strings.Trim(DataSrcName, `"`)
		}

		//Validate DB dialect
		trimmedDB := strings.TrimSpace(dbName)
		if trimmedDB != "" {
			if strings.EqualFold(trimmedDB, "Postgres") {
				DialectID = consts.Postgres
			} else if strings.EqualFold(trimmedDB, "MySql") {
				DialectID = consts.MySQL
			} else if strings.EqualFold(trimmedDB, "Sqlite") {
				DialectID = consts.SQLite
			} else if strings.EqualFold(trimmedDB, "SqlServer") {
				DialectID = consts.SQLServer
			} else if strings.EqualFold(trimmedDB, "Oracle") {
				DialectID = consts.Oracle
			} else if strings.EqualFold(trimmedDB, "DB2") {
				DialectID = consts.DB2
			} else if strings.EqualFold(trimmedDB, "Sybase") {
				DialectID = consts.Sybase
			} else {
				return fmt.Errorf("Invalid DB Name: '%s' provided.", dbName)
			}
		}
	}

	return nil
}

func GetSecurityLevel() consts.SecurityLevel {
	var securityLevel int = 0

	if PrivProtocol != consts.NO_PRIV && !strings.EqualFold(PrivPassword, "") {
		if AuthProtocol != consts.NO_AUTH && !strings.EqualFold(AuthPassword, "") {
			securityLevel = 3
		} else {
			securityLevel = 0
		}
	} else {
		if AuthProtocol != consts.NO_AUTH && !strings.EqualFold(AuthPassword, "") {
			securityLevel = 1
		} else {
			securityLevel = 0
		}
	}

	return consts.SecurityLevel(securityLevel)
}
