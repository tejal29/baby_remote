// Copyright 2017 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/openpgp"

	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/crypto/openpgp/packet"
	"k8s.io/api/admission/v1beta1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

var (
	whitelistNames []string
	tlsCertFile    string
	tlsKeyFile     string
	publicKey      string
	privateKey     string
)

const (
	ANNOTATION = "verified"
	BREAKGLASS = "breakglass"
)

func main() {
	flag.StringVar(&tlsCertFile, "tls-cert-file", "/var/serving-cert/tls.crt", "TLS certificate file.")
	flag.StringVar(&tlsKeyFile, "tls-key-private-file", "/var/serving-cert/tls.key", "TLS key file.")
	flag.StringVar(&publicKey, "--public-key", "/var/gpg_pub//key.pub", "Public File")
	flag.StringVar(&privateKey, "--private-key", "/var/gpg_priv/key.priv", "Private File")

	http.HandleFunc("/", admissionReviewHandler)
	s := http.Server{
		Addr: ":443",
		TLSConfig: &tls.Config{
			ClientAuth: tls.NoClientCert,
		},
	}
	log.Fatal(s.ListenAndServeTLS(tlsCertFile, tlsKeyFile))
}

func admissionReviewHandler(w http.ResponseWriter, r *http.Request) {
	inClusterConfig, err := rest.InClusterConfig()
	status := &v1beta1.AdmissionResponse{Allowed: true}
	if err != nil {
		log.Printf("error %s", err)
	}
	shallowClientConfigCopy := *inClusterConfig
	shallowClientConfigCopy.GroupVersion = &schema.GroupVersion{
		Group:   "babyremote.com",
		Version: "v1alpha1",
	}
	shallowClientConfigCopy.APIPath = "/apis"
	dynamicClient, err := dynamic.NewClient(&shallowClientConfigCopy)
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ar := v1beta1.AdmissionReview{}
	if err := json.Unmarshal(data, &ar); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	pod := v1.Pod{}
	if err := json.Unmarshal(ar.Request.Object.Raw, &pod); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Check if container is already annotated as verified or has breakglass
	annotations := pod.GetAnnotations()
	log.Printf("getting annotations %s", annotations)
	if _, ok := annotations[BREAKGLASS]; ok {
		log.Printf("Annotation %s found. Skipping verification", BREAKGLASS)
		ReturnRequest(status, w)
		return
	}
	if attestation, ok := annotations[ANNOTATION]; ok {
		// Attestation found. Verify it
		if verify(attestation) {
			log.Println("Pod Attestation verified!. Skipping verification")
			ReturnRequest(status, w)
			return
		}
		log.Printf("could not verify attestion on the %s. Continuing with verifcation.", attestation)
	}

	var whitelists []string
	// Get all whitelists
	whitelistCRDs := dynamicClient.Resource(
		&metav1.APIResource{
			Name:       "imagenamewhitelists",
			Namespaced: false,
			Group:      "babyremote.com",
			Version:    "v1alpha1",
			// kind is the kind for the resource (e.g. 'Foo' is the kind for a resource 'foo')
			Kind: "ImageNameWhitelist",
		},
		"",
	)

	t, _ := whitelistCRDs.List(metav1.ListOptions{})
	unstructredList := t.(*unstructured.UnstructuredList)
	bytes, _ := unstructredList.MarshalJSON()
	var nm ImageWhitelistCRD
	json.Unmarshal(bytes, &nm)
	for _, item := range nm.Items {
		log.Printf("\nFound %s whitelist policy namespace: %s, spec %s",
			item.Name, item.Namespace, item.ObjectSpec.Whitelists)
		log.Println("Ignoring namespace filter right now")
		whitelists = append(whitelists, item.ObjectSpec.Whitelists...)
	}
	whitelistSet := make(map[string]bool, len(whitelists))
	for _, s := range whitelists {
		whitelistSet[s] = true
	}
	log.Printf("whitelists %q", whitelistSet)
	for _, container := range pod.Spec.Containers {
		log.Printf("Checking Pod image %s", container.Image)
		if _, ok := whitelistSet[container.Image]; !ok {
			log.Println("Not whitelisted")
			status.Allowed = false
			status.Result = &metav1.Status{
				Status: metav1.StatusFailure, Code: http.StatusForbidden, Reason: metav1.StatusReasonForbidden,
				Message: fmt.Sprintf("%q is not whitelisted", container.Image),
			}
			ReturnRequest(status, w)
			return
		}
		log.Println("whitelisted")
		// Image. Add annotation to the Pod.
		errAnnotate := AnnotatePod(pod, inClusterConfig)
		if errAnnotate != nil {
			log.Printf("Error annotating pod %s", errAnnotate)
		}
		ReturnRequest(status, w)
		return
	}
}

func ReturnRequest(status *v1beta1.AdmissionResponse, w http.ResponseWriter) {
	ar := v1beta1.AdmissionReview{
		Response: status,
	}

	data, err := json.Marshal(ar)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func AnnotatePod(pod v1.Pod, config *rest.Config) error {
	// Create a Kubernetes core/v1 client.
	clientV1, err := corev1client.NewForConfig(config)
	if err != nil {
		return (err)
	}
	if err != nil {
		return err
	}
	// Sign the Pod spec.
	log.Println("\n in annotate")
	privateKeyDec, err := getPrivateKey()
	if err != nil {
		return err
	}
	publicKeyDec, err := getPublicKey()
	if err != nil {
		return err
	}
	b, jsonErr := json.Marshal(pod.Spec)
	if jsonErr != nil {
		return jsonErr
	}
	attestation, err := Sign(publicKeyDec, privateKeyDec, bytes.NewReader(b))
	log.Printf("Getting %s  pod %s", pod.Namespace, pod.Name)
	oldPod, err := clientV1.Pods(pod.Namespace).Get(pod.Name, metav1.GetOptions{})
	log.Println(err)
	log.Printf("Old pod %s\n Pod spec %s", oldPod, pod)
	annotations := oldPod.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[ANNOTATION] = attestation
	oldPod.SetAnnotations(annotations)
	newPod, err := clientV1.Pods(pod.Namespace).Update(oldPod)
	log.Printf("\n Annotation%s", newPod.GetAnnotations())
	return err
}

type ImageWhitelistCRD struct {
	Object map[string]interface{}

	// Items is a list of unstructured objects.
	Items []ImageWhiteList `json:"items"`
}

type ImageWhiteList struct {
	ApiVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	ObjectMeta `json:"metadata"`
	ObjectSpec `json:"spec"`
}

type ObjectMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namepsace"`
	Object    map[string]interface{}
}

type ObjectSpec struct {
	Whitelists []string `json:"whitelist"`
}

func verify(attestation string) bool {
	s, err := base64.StdEncoding.DecodeString(attestation)
	key, err := getPublicKey()
	if err != nil {
		return false
	}
	b, _ := clearsign.Decode(s)

	reader := packet.NewReader(b.ArmoredSignature.Body)
	pkt, err := reader.Next()
	if err != nil {
		log.Println(err)
		return false
	}

	sig, ok := pkt.(*packet.Signature)
	if !ok {
		log.Println("Not signature")
		return false
	}

	hash := sig.Hash.New()
	io.Copy(hash, bytes.NewReader(b.Bytes))

	err = key.VerifySignature(hash, sig)
	if err != nil {
		log.Println("verified signature")
		return true
	}
	return false
}

func getPrivateKey() (*packet.PrivateKey, error) {
	pkt, err := getKey(privateKey, openpgp.PrivateKeyType)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		log.Println("Not private key")
		return nil, err
	}
	return key, nil
}

func getPublicKey() (*packet.PublicKey, error) {
	pkt, err := getKey(publicKey, openpgp.PublicKeyType)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		log.Println("Not public key")
		return nil, err
	}
	return key, nil
}

func getKey(key string, keytype string) (packet.Packet, error) {
	f, err := os.Open(key)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	block, err := armor.Decode(f)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	if block.Type != keytype {
		log.Printf("Not %s", keytype)
		return nil, err
	}
	reader := packet.NewReader(block.Body)
	return reader.Next()
}

func Sign(pubKey *packet.PublicKey, privKey *packet.PrivateKey, message io.Reader) (string, error) {
	signer := createEntityFromKeys(pubKey, privKey)
	var b bytes.Buffer
	err := openpgp.ArmoredDetachSign(&b, signer, message, nil)
	return base64.StdEncoding.EncodeToString(b.Bytes()), err
}

func createEntityFromKeys(pubKey *packet.PublicKey, privKey *packet.PrivateKey) *openpgp.Entity {
	config := packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
		RSABits: 4096,
	}
	currentTime := config.Now()
	uid := packet.NewUserId("", "", "")

	e := openpgp.Entity{
		PrimaryKey: pubKey,
		PrivateKey: privKey,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryId := false

	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimaryId,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	keyLifetimeSecs := uint32(86400 * 365)

	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		PublicKey:  pubKey,
		PrivateKey: privKey,
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			PreferredHash:             []uint8{8}, // SHA-256
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
			KeyLifetimeSecs:           &keyLifetimeSecs,
		},
	}
	return &e
}
