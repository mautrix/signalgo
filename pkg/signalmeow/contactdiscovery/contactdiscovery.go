package contactdiscovery

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/rs/zerolog/log"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/contactdiscovery/contactDiscoveryCrypto"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/contactdiscovery/contactsDiscovery"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/contactdiscovery/transport"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
	"golang.org/x/text/encoding/charmap"
)

var CDS_MRENCLAVE = "c98e00a4e3ff977a56afefe7362a27e4961e4f19e211febfbb19b897e6b80b15"

type Contact struct {
	UUID       string
	Name       string
	E164       string
	ProfileKey []byte
}

// AuthCredentials holds the credentials for the websocket connection
type directoryAuthCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *directoryAuthCredentials) AsBasic() string {
	usernameAndPassword := a.Username + ":" + a.Password
	dec := charmap.Windows1250.NewDecoder()
	out, _ := dec.String(usernameAndPassword)
	encoded := base64.StdEncoding.EncodeToString([]byte(out))
	return "Basic " + encoded
}
func getDirectoryAuthCredentials(d *signalmeow.Device) (*directoryAuthCredentials, error) {
	var DIRECTORY_AUTH_PATH = "/v2/directory/auth"
	username, password := d.Data.BasicAuthCreds()
	opts := &web.HTTPReqOpt{
		Username: &username,
		Password: &password,
	}
	resp, err := web.SendHTTPRequest("GET", DIRECTORY_AUTH_PATH, opts)
	if err != nil {
		return nil, fmt.Errorf("could not get auth credentials %v", err)
	}
	authCredentials := directoryAuthCredentials{}
	err = web.DecodeHTTPResponseBody(&authCredentials, resp)
	if err != nil {
		return nil, fmt.Errorf("could not parse auth credentials %v", err)
	}
	return &authCredentials, nil
}

func LookupPhoneNumber(d *signalmeow.Device, e164Number string) (string, error) {
	numbers, err := LookupPhoneNumbers(d, []string{e164Number})
	if err != nil {
		return "", err
	}
	return numbers[e164Number], nil
}

func LookupPhoneNumbers(d *signalmeow.Device, e164Numbers []string) (map[string]string, error) {
	// regexp for valid phone numbers
	re := regexp.MustCompile(`^(?:(?:\(?(?:00|\+)([1-4]\d\d|[1-9]\d?)\)?)?[\-\.\ \\\/]?)?((?:\(?\d{1,}\)?[\-\.\ \\\/]?){0,})(?:[\-\.\ \\\/]?(?:#|ext\.?|extension|x)[\-\.\ \\\/]?(\d+))?$`)

	// empty UUID
	emptyUUID := "00000000-0000-0000-0000-000000000000"

	submittedNumbersMap := map[string]string{}
	submittedNumbers := []string{}

	// Make sure all numbers are E164 formatted and not duplicates
	for _, phoneNum := range e164Numbers {
		_, inMap := submittedNumbersMap[phoneNum]
		if phoneNum != "" && re.MatchString(phoneNum) && !inMap {
			submittedNumbers = append(submittedNumbers, phoneNum)
			submittedNumbersMap[phoneNum] = emptyUUID
		} else {
			log.Warn().Msgf("skipping invalid or duplicate phone number %s", phoneNum)
		}
	}
	if len(submittedNumbers) == 0 {
		return nil, fmt.Errorf("no valid phone numbers")
	}

	authCredentials, err := getDirectoryAuthCredentials(d)
	log.Debug().Msgf("got auth creds: %v", authCredentials)
	if err != nil {
		return nil, fmt.Errorf("could not get auth credentials %v", err)
	}
	remoteAttestation := contactsDiscovery.RemoteAttestation{}
	attestations, err := remoteAttestation.GetAndVerifyMultiRemoteAttestation(
		CDS_MRENCLAVE,
		authCredentials.Username,
		authCredentials.Password,
	)
	if err != nil {
		return nil, fmt.Errorf("could not get remote attestation %v", err)
	}
	request, err := contactDiscoveryCrypto.CreateDiscoveryRequest(submittedNumbers, attestations)
	if err != nil {
		return nil, fmt.Errorf("could not get create createDiscoveryRequest %v", err)
	}
	log.Debug().Msg("[textsecure] GetRegisteredContacts contactDiscoveryRequest")

	response, err := getContactDiscoveryRegisteredUsers(authCredentials.AsBasic(), request, remoteAttestation.Cookies, CDS_MRENCLAVE)
	if err != nil {
		return nil, fmt.Errorf("could not get get ContactDiscovery %v", err)
	}
	responseData, err := contactDiscoveryCrypto.GetDiscoveryResponseData(*response, attestations)
	if err != nil {
		return nil, fmt.Errorf("could not get get ContactDiscovery data %v", err)
	}
	uuidlength := 16
	ind := 0

	for _, phoneNum := range submittedNumbers {
		UUID := idToHexUUID(responseData[ind*uuidlength : (ind+1)*uuidlength])
		if UUID == emptyUUID {
			UUID = ""
		}
		submittedNumbersMap[phoneNum] = UUID
	}
	return submittedNumbersMap, nil
}

func getContactDiscoveryRegisteredUsers(authorization string, request *contactDiscoveryCrypto.DiscoveryRequest, cookies string, mrenclave string) (*contactDiscoveryCrypto.DiscoveryResponse, error) {
	var CONTACT_DISCOVERY = "/v1/discovery/%s"

	log.Debug().Msg("[textsecure] getContactDiscoveryRegisteredUser")
	body, err := json.Marshal(*request)

	if err != nil {
		return nil, err
	}
	resp, err := transport.DirectoryTransport.PutJSONWithAuthCookies(
		fmt.Sprintf(CONTACT_DISCOVERY, mrenclave),
		body,
		authorization,
		cookies,
	)
	if err != nil {
		return nil, err
	}
	if resp.IsError() {
		return nil, resp
	}
	discoveryResponse := &contactDiscoveryCrypto.DiscoveryResponse{}
	dec := json.NewDecoder(resp.Body)
	log.Debug().Msg("[textsecure] GetAndVerifyMultiRemoteAttestation resp")
	err = dec.Decode(&discoveryResponse)
	if err != nil {
		return nil, err
	}
	return discoveryResponse, nil
	// return nil, fmt.Errorf("fail")
}
func idToHexUUID(id []byte) string {
	msb := id[:8]
	lsb := id[8:]
	msbHex := hex.EncodeToString(msb)
	lsbHex := hex.EncodeToString(lsb)
	return msbHex[:8] + "-" + msbHex[8:12] + "-" + msbHex[12:] + "-" + lsbHex[:4] + "-" + lsbHex[4:]
}
