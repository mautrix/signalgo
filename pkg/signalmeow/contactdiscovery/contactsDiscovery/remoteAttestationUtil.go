package contactsDiscovery

import (
	"encoding/json"
	"fmt"

	"go.mau.fi/mautrix-signal/pkg/signalmeow/contactdiscovery/axolotl"
	textsecureCrypto "go.mau.fi/mautrix-signal/pkg/signalmeow/contactdiscovery/crypto"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"

	log "github.com/rs/zerolog/log"
)

const REMOTE_ATTESTATION_REQUEST = "/v1/attestation/%s"

type RemoteAttestation struct {
	RequestId []byte
	Keys      RemoteAttestationKeys
	Cookies   string
}
type RemoteAttestationRequest struct {
	ClientPublic []byte `json:"clientPublic"`
}

type RemoteAttestationResponse struct {
	ServerEphemeralPublic []byte `json:"serverEphemeralPublic"`
	ServerStaticPublic    []byte `json:"serverStaticPublic"`
	Quote                 []byte `json:"quote"`
	Iv                    []byte `json:"iv"`
	Ciphertext            []byte `json:"ciphertext"`
	Tag                   []byte `json:"tag"`
	Signature             string `json:"signature"`
	// Certificates          string `json:"certificates"`
	// SignatureBody         string `json:"signatureBody"`
}
type RemoteAttestationResponse2 struct {
	ServerEphemeralPublic []byte `json:"serverEphemeralPublic"`
	// ServerStaticPublic    []byte `json:"serverStaticPublic"`
	// Quote                 []byte `json:"quote"`
	// Iv         []byte `json:"iv"`
	// Ciphertext []byte `json:"ciphertext"`
	// Tag        []byte `json:"tag"`
	// Signature             string `json:"signature"`
	// Certificates          string `json:"certificates"`
	// SignatureBody         string `json:"signatureBody"`
}
type MultiRemoteAttestationResponse struct {
	Attestations map[string]*RemoteAttestationResponse `json:"attestations"`
}
type MultiRemoteAttestationResponse2 struct {
	// Attestations map[string]*RemoteAttestationResponse2 `json:"attestations"`
}
type RemoteAttestationKeys struct {
	ClientKey []byte
	ServerKey []byte
}

func (r *RemoteAttestation) GetAndVerifyMultiRemoteAttestation(
	enclaveName string,
	username string,
	password string,
) (map[string]*RemoteAttestation, error) {
	log.Debug().Msg("[textsecure] GetAndVerifyMultiRemoteAttestation")

	keyPair := axolotl.NewECKeyPair()
	publicKey := keyPair.PublicKey.Key()
	remoteAttestationRequest := RemoteAttestationRequest{
		ClientPublic: publicKey[:],
	}

	body, err := json.Marshal(remoteAttestationRequest)
	if err != nil {
		return nil, err
	}

	path := fmt.Sprintf(REMOTE_ATTESTATION_REQUEST, enclaveName)
	resp, err := web.SendHTTPRequest("PUT", path, &web.HTTPReqOpt{
		Host:        "api.directory.signal.org",
		Body:        body,
		ContentType: web.ContentTypeJSON,
		Username:    &username,
		Password:    &password,
	})
	//resp, err := transport.DirectoryTransport.PutJSONWithAuth(
	//	fmt.Sprintf(REMOTE_ATTESTATION_REQUEST, enclaveName),
	//	body,
	//	authorization,
	//)
	if err != nil {
		return nil, err
	}
	cookies := resp.Header.Get("Set-Cookie")
	log.Debug().Msgf("[textsecure] GetAndVerifyMultiRemoteAttestation cookies: %v", cookies)

	multiRemoteAttestationResponse := &MultiRemoteAttestationResponse{}
	dec := json.NewDecoder(resp.Body)
	log.Debug().Msgf("[textsecure] GetAndVerifyMultiRemoteAttestation resp: %v", resp)
	err = dec.Decode(&multiRemoteAttestationResponse)
	if err != nil {
		return nil, err
	}
	if len(multiRemoteAttestationResponse.Attestations) < 1 || len(multiRemoteAttestationResponse.Attestations) > 3 {
		return nil, fmt.Errorf("Incorrect number of attestations: " + fmt.Sprint(len(multiRemoteAttestationResponse.Attestations)))
	}
	assestations := map[string]*RemoteAttestation{}
	for key, remoteAttestationResponse := range multiRemoteAttestationResponse.Attestations {
		log.Debug().Msg("[textsecure] GetAndVerifyMultiRemoteAttestation key ")

		r.Cookies = cookies
		assestation, err := validateAndBuildRemoteAttestation(remoteAttestationResponse,
			cookies,
			// KeyStore, -> Android secret iaskeystore
			keyPair,
			enclaveName,
		)
		if err != nil {
			log.Err(err).Msg("[textsecure] GetAndVerifyMultiRemoteAttestation validation")
		} else {
			assestations[key] = assestation

		}
	}

	return assestations, nil
}

func validateAndBuildRemoteAttestation(
	remoteAttestation *RemoteAttestationResponse,
	cookies string,
	// keystore,
	keyPair *axolotl.ECKeyPair,
	enclaveName string,
) (*RemoteAttestation, error) {
	keys, err := remoteAttestationKeys(keyPair, remoteAttestation.ServerEphemeralPublic, remoteAttestation.ServerStaticPublic)
	log.Debug().Msg("[textsecure] validateAndBuildRemoteAttestation ")
	if err != nil {
		return nil, err
	}
	requestID, err := getRequestId(keys, remoteAttestation)
	if err != nil {
		return nil, err
	}
	// Quote                 quote     = new Quote(response.getQuote()); -> quote.go -> not necessary if we strip the verification

	// RemoteAttestationCipher.verifyServerQuote(quote, response.getServerStaticPublic(), mrenclave);

	// RemoteAttestationCipher.verifyIasSignature(iasKeyStore, response.getCertificates(), response.getSignatureBody(), response.getSignature(), quote);
	return &RemoteAttestation{
		Keys: *keys,
		// Quote:,
		RequestId: requestID,
	}, nil

}

func remoteAttestationKeys(keyPair *axolotl.ECKeyPair, serverPublicEphemarl []byte, serverPublicStatic []byte) (*RemoteAttestationKeys, error) {

	ephemeralToEphemeral := [32]byte{}
	serverPublicEphemarlPublicKey := axolotl.NewECPublicKey(serverPublicEphemarl).GetKey()
	axolotl.CalculateAgreement(&ephemeralToEphemeral, &serverPublicEphemarlPublicKey, keyPair.PrivateKey.Key())

	ephemeralToStatic := [32]byte{}
	serverPublicStaticPublicKey := axolotl.NewECPublicKey(serverPublicStatic).GetKey()
	axolotl.CalculateAgreement(&ephemeralToStatic, &serverPublicStaticPublicKey, keyPair.PrivateKey.Key())

	masterSecret := append(ephemeralToEphemeral[:], ephemeralToStatic[:]...)
	publicKeys := append(append(keyPair.PublicKey.Key()[:], serverPublicEphemarl...), serverPublicStatic...)

	keys, err := axolotl.DeriveSecrets(masterSecret, publicKeys, nil, 64)
	if err != nil {
		return nil, err
	}

	clientKey := keys[:32]
	serverKey := keys[32:64]
	return &RemoteAttestationKeys{
		ClientKey: clientKey,
		ServerKey: serverKey,
	}, nil

}

func getRequestId(keys *RemoteAttestationKeys, response *RemoteAttestationResponse) ([]byte, error) {
	return textsecureCrypto.AesgcmDecrypt(keys.ServerKey, response.Iv, response.Ciphertext, response.Tag)
}
