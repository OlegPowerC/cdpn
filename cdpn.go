/*
* For building, need WebNMS library (https://www.webnms.com/go-snmpapi/index.html)
* Author Oleg Volkov, PowerC
* Options:
* [-d]                				 - Debug output. By default off.
* [-c] <community>    				 - community String. By default "public".
* [-p] <port>         				 - remote port no. By default 161.
* [-t] <timeout>      				 - Timeout. By default 5000ms.
* [-r] <retries>      				 - Retries. By default 0.
* [-v] <version>      				 - version(v1 / v2 / v3). By default v1.
* [-u] <username>     				 - The v3 principal/userName
* [-a] <authProtocol>  			 - The authProtocol(MD5/SHA). Mandatory if authPassword is specified
* [-pp]<privProtocol> 				 - The privProtocol(DES/3DES/AES-128/AES-192/AES-256).
* [-w] <authPassword> 				 - The authentication password.
* [-s] <privPassword> 				 - The privacy protocol password. Must be accompanied with auth password and authProtocol fields.
* [-n] <contextName>  				 - The contextName to be used for the v3 pdu.
* [-e] <engineID>					 - Remote Engine's EngineID.
* host Mandatory      				 - The RemoteHost (agent).Format (string without double qoutes/IpAddress).
*/

package main

import (
	fp "./parser2"
	"webnms/snmp"
	"webnms/snmp/consts"
	"webnms/snmp/msg"
	"webnms/snmp/snmpvar"
	"fmt"
	"os"
	"webnms/snmp/util"
	"container/list"
	"strconv"
	"text/tabwriter"
)

//Проверяем, тот OID который мы получили, в том же поддереве или нет
//Параметры - OID с которого начали обход, и принятый ответ
func (m *msncpcl) inSubTree(root []uint32, pdu msg.SnmpMessage) bool {
	oid := pdu.ObjectIDAt(0)
	if oid == nil {
		return false
	}
	oidArray := oid.Value()
	if len(oidArray) < len(root) {
		return false
	}

	for i, v := range root {
		if oidArray[i] != v {
			return false
		}
	}
	return true
}

//Получение имени коммутатора и платформы, параметры, указатель на list с описанием коммутатора, указатель на сессию
//Возвращает Имя и Платформу
func (m *msncpcl) GetSwData(sw *switchhard, lses  *snmp.SnmpSession) (string,string){
	udplocal := snmp.NewUDPProtocolOptions()
	udplocal.SetRemoteHost(sw.ip)
	udplocal.SetRemotePort(fp.Port)
	lses.SetProtocolOptions(udplocal)

	retvar := [2]string{"",""}
	seqoid := [2]string{".1.3.6.1.2.1.1.5",".1.3.6.1.2.1.1.1"}
	lmesg := m.commonsnmpmsg.CopyWithoutVarBinds()
	var loid *snmpvar.SnmpOID
	for i:=0;i<2;i++{
		loid = snmpvar.NewSnmpOID(seqoid[i])
		lmesg.AddNull(*loid)
		lmesg.SetCommand(consts.GetNextRequest)
		if lresp, err := lses.SyncSend(*lmesg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		} else {
			var lt byte
			for _,alresp := range lresp.VarBinds(){
				lt = alresp.Variable().Type()
				switch(lt){
				case consts.OctetString : retvar[i] =alresp.Variable().String(); break
				default:
					break
				}
			}
		}
	}
	return retvar[0],retvar[1]
}

//Конвертируем Hexadecimal в строку
//если нет адреса - то вернем 0.0.0.0
func (m *msncpcl) ConvStIpToString(stip string) string{
	arst := [4]byte{0,0,0,0}
	copy(arst[:],stip)
	return (strconv.Itoa(int(arst[0]))+"."+strconv.Itoa(int(arst[1]))+"."+strconv.Itoa(int(arst[2]))+"."+strconv.Itoa(int(arst[3])))
}

//Получаем список портов на которых есть CDP соседи, а затем список соседей
//заполняем List с описание коммутатора и портов
func (m *msncpcl) WalkPorts(sw *switchhard, lses  *snmp.SnmpSession){

	//OID по которому находим портв с CDP соседями
	seqoid := [1]string{".1.3.6.1.4.1.9.9.23.1.2.1.1.7"}

	udplocal := snmp.NewUDPProtocolOptions()
	udplocal.SetRemoteHost(sw.ip)
	udplocal.SetRemotePort(fp.Port)
	lses.SetProtocolOptions(udplocal)

	lmesg := m.commonsnmpmsg.CopyWithoutVarBinds()
	var loid *snmpvar.SnmpOID
	loid = snmpvar.NewSnmpOID(seqoid[0])
	lmesg.AddNull(*loid)

	for{
		if lresp, err := lses.SyncSend(*lmesg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		} else {
			if lresp.ErrorStatus() != 0 {
				fmt.Println(lresp.ErrorString())
				break
			}
			if !(m.inSubTree(loid.Value(), *lresp)) {
				break
			} else {

				oid := lresp.ObjectIDAt(0)	//OID который получен в ответе
				oar := oid.Value()

				portindvar := oar[len(oar)-2]	//Получаем ID порта
				cdprecnovar := oar[len(oar)-1]	//Получаем номер записи CDP

				sw.swportsl.PushFront(new(swports))								//Создаем новую структуру и добавляем ее в список
				sw.swportsl.Front().Value.(*swports).portid = portindvar		//Заполняем ее поля
				sw.swportsl.Front().Value.(*swports).cdpportindex = cdprecnovar

				walkMsg := lmesg.CopyWithoutVarBinds()
				if oid != nil {
					walkMsg.AddNull(*oid)
				}
				lmesg = walkMsg
			}
		}
	}

	lmesg.SetCommand(consts.GetRequest)	//Переключаемя на GetRequest

	//Список префиксов OID к которым добавляем ID порта и номер записи CDP
	oidportnamepref :=  [5]string {".1.3.6.1.2.1.31.1.1.1.1.",".1.3.6.1.4.1.9.9.23.1.2.1.1.6.",".1.3.6.1.4.1.9.9.23.1.2.1.1.7.",".1.3.6.1.4.1.9.9.23.1.2.1.1.4.",".1.3.6.1.4.1.9.9.23.1.2.1.1.8."}

	for elein := sw.swportsl.Front();elein != nil; elein = elein.Next(){
		indstr := elein.Value.(*swports).portid
		cdpind := elein.Value.(*swports).cdpportindex
		oidportname := oidportnamepref[0]+string(strconv.Itoa(int(indstr)))
		oidportnameo := snmpvar.NewSnmpOID(oidportname)
		getMsg := lmesg.CopyWithoutVarBinds()
		getMsg.AddNull(*oidportnameo)
		stinsar := [5]string{"","","","",""}
		for i := 0; i < 5; i++{
			//Получение имени порта
			if lresp, err := lses.SyncSend(*getMsg); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			} else {
				var lt byte
				for _,alresp := range lresp.VarBinds(){
					lt = alresp.Variable().Type()
					switch(lt){
					case consts.OctetString :  stinsar[i] = alresp.Variable().String(); break
					default:
						break
					}
					if i == 3{
						//Приведение IP адреса к читаемому виду
						stinsar[i] = m.ConvStIpToString(alresp.Variable().String())
					}
				}
			}
			if i < 4 {
				oidportname = oidportnamepref[i+1]+string(strconv.Itoa(int(indstr)))+"."+string(strconv.Itoa(int(cdpind)))
				getsecondMsg := lmesg.CopyWithoutVarBinds()
				oidportnameo := snmpvar.NewSnmpOID(oidportname)
				getsecondMsg.AddNull(*oidportnameo)
				getMsg = getsecondMsg
			}
		}
		elein.Value.(*swports).portname = stinsar[0]
		elein.Value.(*swports).neiname = stinsar[1]
		elein.Value.(*swports).portnei = stinsar[2]
		elein.Value.(*swports).ipnei = stinsar[3]
		elein.Value.(*swports).platformnei = stinsar[4]
	}
}

//Общая структура с методами
type msncpcl struct{
	commonsnmpmsg msg.SnmpMessage	//Общие на всех параметры
	sw list.List					//Список коммутаторов List стркутур switchhard
}

//Описание портов
type swports struct{
	portid uint32			//ID в OID предпослендяя
	cdpportindex uint32		//ID CDP записи в OID последняя часть
	portname string			//Имя порта
	neiname string			//ID соседа
	portnei string			//Порт соседа
	ipnei string			//IP соседа
	platformnei string		//Платформа соседа
}

//Описание конкретного коммутатора
type switchhard struct {
	ip string				//IP адрес
	swportsl list.List		//Список портов - List структур типа swports
	descr string			//описание - обычно платформа
	name string				//Имя - Hostname
}

func main() {
	var st msncpcl

	var usage = "cdpn [-d] [-v version(v1,v2, v3)] [-c community] \n" +
		"[-p port] [-r retries] [-t timeout]" + "\n" +
		"[-u username] [-n contextname] [-a authprotocol (MD5/SHA)] [-w authpassword]" + "\n" +
		"[-pp privprotocol (DES/3DES/AES-128/AES-192/AES-256)] [-s privpassword] [-e engineID] <Switch IP address>"
	var err error

	//Проверка полученых флагов
	if err = fp.ValidateFlags(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, "Usage:", "\n"+usage)
		os.Exit(1)
	}

	//Проверка сколько необходимых параметров получено
	if len(fp.RemArgs) < 1 {
		fmt.Fprintln(os.Stderr, "Usage:", "\n"+usage)
		os.Exit(1)
	}

	//Create new SnmpAPI and SnmpSession instance
	api := snmp.NewSnmpAPI()
	ses := snmp.NewSnmpSession(api)
	api.SetDebug(fp.Debug)

	//Create UDP options and set it on the SnmpSession
	udp := snmp.NewUDPProtocolOptions()
	udp.SetRemoteHost(fp.RemArgs[0])
	//var switchtable allswitches
	st.sw.PushBack(new(switchhard))

	st.sw.Front().Value.(*switchhard).ip = fp.RemArgs[0]

	//Если порт не задан - то 161
	if fp.Port == 0 {
		fp.Port = 161
	}
	udp.SetRemotePort(fp.Port)
	ses.SetProtocolOptions(udp)

	//Open a new SnmpSession
	if err = ses.Open(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer ses.Close() //Close the SnmpSession in any case
	defer api.Close() //Close the SnmpAPI in any case

	st.commonsnmpmsg = msg.NewSnmpMessage()
	if fp.Version == consts.Version3 {
		err = util.Init_V3_LCD(ses,
			udp,
			fp.UserName,
			fp.EngineID, //validation should be done
			fp.AuthProtocol,
			fp.AuthPassword,
			fp.PrivProtocol,
			fp.PrivPassword,
			true, //Validate User
		)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		st.commonsnmpmsg.SetUserName(fp.UserName)
		st.commonsnmpmsg.SetContextName(fp.ContextName)
		//Set the security level for the msg.
		st.commonsnmpmsg.SetSecurityLevel(fp.GetSecurityLevel())
	}

	//Construct SnmpMessage
	st.commonsnmpmsg.SetVersion(fp.Version)
	st.commonsnmpmsg.SetCommunity(fp.Community)
	st.commonsnmpmsg.SetCommand(consts.GetNextRequest)
	st.commonsnmpmsg.SetRetries(fp.Retries)
	st.commonsnmpmsg.SetTimeout(fp.Timeout)

	swname,swos := st.GetSwData(st.sw.Front().Value.(*switchhard),ses)
	st.WalkPorts(st.sw.Front().Value.(*switchhard),ses)
	fmt.Println("Host IP: "+st.sw.Front().Value.(*switchhard).ip)
	fmt.Println("Hostname: "+swname+"\r")
	fmt.Println("Platform: "+swos)
	fmt.Println("\r\n")
	var stlisttab list.List
	for elein := st.sw.Front().Value.(*switchhard).swportsl.Front();elein != nil; elein = elein.Next(){
		stlisttab.PushFront(elein.Value.(*swports).portname + "\t" + elein.Value.(*swports).neiname + "\t" + elein.Value.(*swports).portnei + "\t" + elein.Value.(*swports).platformnei+"\t"+elein.Value.(*swports).ipnei)
	}
	stlisttab.PushFront("---------------\t---------------\t---------------\t--------------------\t---------------")
	stlisttab.PushFront("Local Port\tNeighbor ID\tNeighbor Port\tNeighbor Platform\tNeighbor IP")
	c := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0 )
	for elein2 := stlisttab.Front();elein2 != nil; elein2 = elein2.Next(){
		fmt.Fprintln(c,elein2.Value)
	}
	c.Flush()
}
