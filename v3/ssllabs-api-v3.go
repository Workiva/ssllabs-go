/* Package ssllabs implements a client for using the full range of the Qualys SSLLabs API.
 * It is a refactor of the reference client implementation written by SSLLabs and used in their
 * ssllabs-scan CLI client. The original can be found here:
 * https://github.com/ssllabs/ssllabs-scan/blob/64e93cc6666b411aed5191948204067ddf9a81b0/ssllabs-scan-v3.go
 * and is licensed using the Apache 2.0 Open Source License.
 *
 * The goals for this refactor were:
 *   1. Provide the API functionality as a Library.
 *   2. Implement better compliance with Go best practices.
 *
 * This library provides an SSLLabsClient struct which can be used to easily run scans against any
 * number of publically accessible hosts. Please be mindful of the SSLLabs Terms of Service:
 * https://www.ssllabs.com/about/terms.html
 *
 * For details on consuming the report data returned to and by this library, please refer to the
 * complete documentation of the SSLLabs APIv3 which can be found here:
 * https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md
 */
package ssllabs

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/juju/loggo"
)

var log = loggo.GetLogger("")

const USER_AGENT = "ssllabs-scan v1.5.0 (dev $Id$)"

/*
 * API Data Structures.
 */
type LabsError struct {
	Field   string
	Message string
}

type LabsErrorResponse struct {
	ResponseErrors []LabsError `json:"errors"`
}

func (e LabsErrorResponse) Error() string {
	msg, err := json.Marshal(e)
	if err != nil {
		return err.Error()
	} else {
		return string(msg)
	}
}

type LabsKey struct {
	Size       int
	Strength   int
	Alg        string
	DebianFlaw bool
	Q          int
}

type LabsCaaRecord struct {
	Tag   string
	Value string
	Flags int
}

type LabsCaaPolicy struct {
	PolicyHostname string
	CaaRecords     []LabsCaaRecord
}

type LabsCert struct {
	Id                     string
	Subject                string
	CommonNames            []string
	AltNames               []string
	NotBefore              int64
	NotAfter               int64
	IssuerSubject          string
	SigAlg                 string
	RevocationInfo         int
	CrlURIs                []string
	OcspURIs               []string
	RevocationStatus       int
	CrlRevocationStatus    int
	OcspRevocationStatus   int
	DnsCaa                 bool
	Caapolicy              LabsCaaPolicy
	MustStaple             bool
	Sgc                    int
	ValidationType         string
	Issues                 int
	Sct                    bool
	Sha1Hash               string
	PinSha256              string
	KeyAlg                 string
	KeySize                int
	KeyStrength            int
	KeyKnownDebianInsecure bool
	Raw                    string
}

type LabsChainCert struct {
	Subject              string
	Label                string
	NotBefore            int64
	NotAfter             int64
	IssuerSubject        string
	IssuerLabel          string
	SigAlg               string
	Issues               int
	KeyAlg               string
	KeySize              int
	KeyStrength          int
	RevocationStatus     int
	CrlRevocationStatus  int
	OcspRevocationStatus int
	Raw                  string
}

type LabsChain struct {
	Certs  []LabsChainCert
	Issues int
}

type LabsProtocol struct {
	Id               int
	Name             string
	Version          string
	V2SuitesDisabled bool
	Q                int
}

type LabsSimClient struct {
	Id          int
	Name        string
	Platform    string
	Version     string
	IsReference bool
}

type LabsSimulation struct {
	Client         LabsSimClient
	ErrorCode      int
	ErrorMessage   string
	Attempts       int
	CertChainId    string
	ProtocolId     int
	SuiteId        int
	SuiteName      string
	KxType         string
	KxStrength     int
	DhBits         int
	DhP            int
	DhG            int
	DhYs           int
	NamedGroupBits int
	NamedGroupId   int
	NamedGroupName string
	AlertType      int
	AlertCode      int
	KeyAlg         string
	KeySize        int
	SigAlg         string
}

type LabsSimDetails struct {
	Results []LabsSimulation
}

type LabsSuite struct {
	Id             int
	Name           string
	CipherStrength int
	KxType         string
	KxStrength     int
	DhBits         int
	DhP            int
	DhG            int
	DhYs           int
	NamedGroupBits int
	NamedGroupId   int
	NamedGroudName string
	Q              int
}

type LabsSuites struct {
	Protocol   int
	List       []LabsSuite
	Preference bool
}

type LabsHstsPolicy struct {
	LONG_MAX_AGE      int64
	Header            string
	Status            string
	Error             string
	MaxAge            int64
	IncludeSubDomains bool
	Preload           bool
	Directives        map[string]string
}

type LabsHstsPreload struct {
	Source     string
	HostName   string
	Status     string
	Error      string
	SourceTime int64
}

type LabsHpkpPin struct {
	HashFunction string
	Value        string
}

type LabsHpkpDirective struct {
	Name  string
	Value string
}

type LabsHpkpPolicy struct {
	Header            string
	Status            string
	Error             string
	MaxAge            int64
	IncludeSubDomains bool
	ReportUri         string
	Pins              []LabsHpkpPin
	MatchedPins       []LabsHpkpPin
	Directives        []LabsHpkpDirective
}

type LabsDrownHost struct {
	Ip      string
	Export  bool
	Port    int
	Special bool
	Sslv2   bool
	Status  string
}

type LabsCertChain struct {
	Id        string
	CertIds   []string
	Trustpath []LabsTrustPath
	Issues    int
	NoSni     bool
}

type LabsTrustPath struct {
	CertIds       []string
	Trust         []LabsTrust
	IsPinned      bool
	MatchedPins   int
	UnMatchedPins int
}

type LabsTrust struct {
	RootStore         string
	IsTrusted         bool
	TrustErrorMessage string
}

type LabsNamedGroups struct {
	List       []LabsNamedGroup
	Preference bool
}

type LabsNamedGroup struct {
	Id   int
	Name string
	Bits int
}

type LabsHttpTransaction struct {
	RequestUrl        string
	StatusCode        int
	RequestLine       string
	RequestHeaders    []string
	ResponseLine      string
	ResponseRawHeader []string
	ResponseHeader    []LabsHttpHeader
	FragileServer     bool
}

type LabsHttpHeader struct {
	Name  string
	Value string
}

type LabsEndpointDetails struct {
	HostStartTime                  int64
	CertChains                     []LabsCertChain
	Protocols                      []LabsProtocol
	Suites                         []LabsSuites
	NoSniSuites                    LabsSuites
	NamedGroups                    LabsNamedGroups
	ServerSignature                string
	PrefixDelegation               bool
	NonPrefixDelegation            bool
	VulnBeast                      bool
	RenegSupport                   int
	SessionResumption              int
	CompressionMethods             int
	SupportsNpn                    bool
	NpnProtocols                   string
	SupportsAlpn                   bool
	AlpnProtocols                  string
	SessionTickets                 int
	OcspStapling                   bool
	StaplingRevocationStatus       int
	StaplingRevocationErrorMessage string
	SniRequired                    bool
	HttpStatusCode                 int
	HttpForwarding                 string
	SupportsRc4                    bool
	Rc4WithModern                  bool
	Rc4Only                        bool
	ForwardSecrecy                 int
	ProtocolIntolerance            int
	MiscIntolerance                int
	Sims                           LabsSimDetails
	Heartbleed                     bool
	Heartbeat                      bool
	OpenSslCcs                     int
	OpenSSLLuckyMinus20            int
	Ticketbleed                    int
	Bleichenbacher                 int
	Poodle                         bool
	PoodleTLS                      int
	FallbackScsv                   bool
	Freak                          bool
	HasSct                         int
	DhPrimes                       []string
	DhUsesKnownPrimes              int
	DhYsReuse                      bool
	EcdhParameterReuse             bool
	Logjam                         bool
	ChaCha20Preference             bool
	HstsPolicy                     LabsHstsPolicy
	HstsPreloads                   []LabsHstsPreload
	HpkpPolicy                     LabsHpkpPolicy
	HpkpRoPolicy                   LabsHpkpPolicy
	HttpTransactions               []LabsHttpTransaction
	DrownHosts                     []LabsDrownHost
	DrownErrors                    bool
	DrownVulnerable                bool
}

type LabsEndpoint struct {
	IpAddress            string
	ServerName           string
	StatusMessage        string
	StatusDetailsMessage string
	Grade                string
	GradeTrustIgnored    string
	FutureGrade          string
	HasWarnings          bool
	IsExceptional        bool
	Progress             int
	Duration             int
	Eta                  int
	Delegation           int
	Details              LabsEndpointDetails
}

type LabsReport struct {
	Host            string
	Port            int
	Protocol        string
	IsPublic        bool
	Status          string
	StatusMessage   string
	StartTime       int64
	TestTime        int64
	EngineVersion   string
	CriteriaVersion string
	CacheExpiryTime int64
	CertHostnames   []string
	Endpoints       []LabsEndpoint
	Certs           []LabsCert
	rawJSON         string
}

type LabsResults struct {
	Reports   []LabsReport
	Responses []string
}

type LabsInfo struct {
	EngineVersion        string
	CriteriaVersion      string
	MaxAssessments       int
	currentAssessments   int
	NewAssessmentCoolOff int64
	Messages             []string
}

type Event struct {
	host      string
	eventType int
	report    *LabsReport
}

/*
 * Client Implementation.
 */

const (
	ASSESSMENT_FAILED   = -1
	ASSESSMENT_STARTING = 0
	ASSESSMENT_COMPLETE = 1
)

// HostProvider is used as a queue for scans to request and to query.
type HostProvider struct {
	hostnames   []string
	StartingLen int
}

func NewHostProvider(hs []string) *HostProvider {
	hostnames := make([]string, len(hs))
	copy(hostnames, hs)
	hostProvider := HostProvider{hostnames, len(hs)}
	return &hostProvider
}

func (hp *HostProvider) next() (string, bool) {
	if len(hp.hostnames) == 0 {
		return "", false
	}

	var e string
	e, hp.hostnames = hp.hostnames[0], hp.hostnames[1:]

	return e, true
}

func (hp *HostProvider) retry(host string) {
	hp.hostnames = append(hp.hostnames, host)
}

// SSLLabsClientIface should be used to aid the writing of tests.
type SSLLabsClientIface interface {
	Results() *LabsResults
	Run() error
}

// SSLLabsClient is the primary tool for interacting with the API.
type SSLLabsClient struct {
	// How many assessment do we have in progress?
	activeAssessments int
	// How many assessments does the server think we have in progress?
	currentAssessments int
	// The maximum number of assessments we can have in progress at any one time.
	maxAssessments int
	requestCounter uint64

	hostProvider         *HostProvider
	FrontendEventChannel chan Event
	BackendEventChannel  chan Event
	results              *LabsResults
	httpClient           *http.Client
	apiLocation          string
	newAssessmentCoolOff int64
	ignoreMismatch       bool
	startNew             bool
	fromCache            bool
	maxAge               int
}

// SSLLabsClientConfig provides a set of settings you can use when creating an SSLLabsClient to
// tweak how the client interacts with the API. These options are mostly documented here:
// https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md#protocol-calls.
type SSLLabsClientConfig struct {
	ApiLocation          string
	NewAssessmentCoolOff int64
	IgnoreMismatch       bool
	StartNew             bool
	FromCache            bool
	MaxAge               int
	Insecure             bool
}

func NewSSLLabsClientWithConfig(hosts []string, config *SSLLabsClientConfig) *SSLLabsClient {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: config.Insecure},
		DisableKeepAlives: false,
		Proxy:             http.ProxyFromEnvironment,
	}

	client := SSLLabsClient{
		hostProvider:         NewHostProvider(hosts),
		FrontendEventChannel: make(chan Event),
		BackendEventChannel:  make(chan Event),
		results:              &LabsResults{Reports: make([]LabsReport, 0)},
		httpClient:           &http.Client{Transport: transport},
		apiLocation:          config.ApiLocation,
		newAssessmentCoolOff: config.NewAssessmentCoolOff,
		ignoreMismatch:       config.IgnoreMismatch,
		startNew:             config.StartNew,
		fromCache:            config.FromCache,
		maxAge:               config.MaxAge,
	}

	return &client
}

// NewSSLLabsClient returns an SSLLabsClient with sane defaults.
func NewSSLLabsClient(hosts []string) *SSLLabsClient {
	return NewSSLLabsClientWithConfig(
		hosts,
		&SSLLabsClientConfig{
			ApiLocation:          "https://api.ssllabs.com/api/v3",
			NewAssessmentCoolOff: 1100,
			IgnoreMismatch:       true,
			StartNew:             false,
			FromCache:            true,
			MaxAge:               48,
			Insecure:             false,
		},
	)
}

// Results should be invoked after Run has completed to fetch the outcome of the scan(s).
func (c *SSLLabsClient) Results() *LabsResults {
	return c.results
}

// Run will trigger the SSLLabsClient to request scan data from the API and will block while it
// polls the API until all the results become available.
func (c *SSLLabsClient) Run() error {
	// Ping SSL Labs to determine how many concurrent
	// assessments we're allowed to use. Print the API version
	// information and the limits.
	labsInfo, err := c.invokeInfo()
	if err != nil {
		log.Debugf("Could not get API Info: %v", err)
		close(c.FrontendEventChannel)
		return err
	}

	log.Debugf("SSL Labs v%v (criteria version %v)", labsInfo.EngineVersion, labsInfo.CriteriaVersion)

	if log.EffectiveLogLevel() <= loggo.DEBUG {
		for _, message := range labsInfo.Messages {
			log.Debugf("Server message: %v", message)
		}
	}

	c.maxAssessments = labsInfo.MaxAssessments

	if c.maxAssessments <= 0 {
		log.Warningf("You're not allowed to request new assessments")
	}

	moreAssessments := true

	if labsInfo.NewAssessmentCoolOff >= 1000 {
		c.newAssessmentCoolOff = 100 + labsInfo.NewAssessmentCoolOff
	} else {
		log.Warningf("Info.NewAssessmentCoolOff too small: %v", labsInfo.NewAssessmentCoolOff)
	}

	// Spawn and wait for API worker threads to return events.
	for {
		select {
		// Handle assessment events (e.g., starting and finishing).
		case e := <-c.BackendEventChannel:
			if e.eventType == ASSESSMENT_FAILED {
				c.activeAssessments--
				c.hostProvider.retry(e.host)
			}

			if e.eventType == ASSESSMENT_STARTING {
				log.Debugf("Assessment starting: %v", e.host)
			}

			if e.eventType == ASSESSMENT_COMPLETE {
				msg := ""

				l := loggo.DEBUG
				if len(e.report.Endpoints) == 0 {
					msg = fmt.Sprintf("Assessment failed: %v (%v)", e.host, e.report.StatusMessage)
					l = loggo.ERROR
				} else if len(e.report.Endpoints) > 1 {
					msg = fmt.Sprintf("Assessment complete: %v (%v hosts in %v seconds)",
						e.host, len(e.report.Endpoints), (e.report.TestTime-e.report.StartTime)/1000)
				} else {
					msg = fmt.Sprintf("Assessment complete: %v (%v host in %v seconds)",
						e.host, len(e.report.Endpoints), (e.report.TestTime-e.report.StartTime)/1000)
				}

				for _, endpoint := range e.report.Endpoints {
					if endpoint.Grade != "" {
						msg = msg + "\n    " + endpoint.IpAddress + ": " + endpoint.Grade
						if endpoint.FutureGrade != "" {
							msg = msg + " -> " + endpoint.FutureGrade
						}
					} else {
						msg = msg + "\n    " + endpoint.IpAddress + ": Err: " + endpoint.StatusMessage
					}
				}

				log.Logf(l, msg)

				c.activeAssessments--

				c.results.Reports = append(c.results.Reports, *e.report)
				c.results.Responses = append(c.results.Responses, e.report.rawJSON)

				log.Debugf("active assessments: %v (more: %v)", c.activeAssessments, moreAssessments)
			}

			// Are we done?
			if (c.activeAssessments == 0) && (moreAssessments == false) {
				close(c.FrontendEventChannel)
				return nil
			}

		// Once a second, start a new assessment, provided there are
		// hostnames left and we're not over the concurrent assessment limit.
		default:
			if c.hostProvider.StartingLen > 0 {
				<-time.NewTimer(time.Duration(c.newAssessmentCoolOff) * time.Millisecond).C
			}

			if moreAssessments {
				if c.currentAssessments < c.maxAssessments {
					host, hasNext := c.hostProvider.next()
					if hasNext {
						c.startAssessment(host)
					} else {
						// We've run out of hostnames and now just need
						// to wait for all the assessments to complete.
						moreAssessments = false

						if c.activeAssessments == 0 {
							close(c.FrontendEventChannel)
							return nil
						}
					}
				}
			}
		}
	}
}

// startAssessment will spawn an API worker thread and increment the count of activeAssessments.
func (c *SSLLabsClient) startAssessment(h string) {
	go c.newAssessment(h)
	c.activeAssessments++
}

// newAssessment is the entry point for an API worker, and will request an assessment and poll for
// its results.
func (c *SSLLabsClient) newAssessment(host string) {
	c.BackendEventChannel <- Event{host, ASSESSMENT_STARTING, nil}

	var report *LabsReport
	var startTime int64 = -1
	var startNew = c.startNew

	for {
		myResponse, err := c.invokeAnalyze(host, startNew, c.fromCache)
		if err != nil {
			c.BackendEventChannel <- Event{host, ASSESSMENT_FAILED, nil}
			return
		}

		if startTime == -1 {
			startTime = myResponse.StartTime
			startNew = false
		} else {
			// Abort this assessment if the time we receive in a follow-up check
			// is older than the time we got when we started the request. The
			// upstream code should then retry the hostname in order to get
			// consistent results.
			if myResponse.StartTime > startTime {
				c.BackendEventChannel <- Event{host, ASSESSMENT_FAILED, nil}
				return
			} else {
				startTime = myResponse.StartTime
			}
		}

		if (myResponse.Status == "READY") || (myResponse.Status == "ERROR") {
			report = myResponse
			break
		}

		time.Sleep(5 * time.Second)
	}

	c.BackendEventChannel <- Event{host, ASSESSMENT_COMPLETE, report}
}

func (c *SSLLabsClient) invokeGetRepeatedly(url string) (*http.Response, []byte, error) {
	retryCount := 0

	for {
		var reqId = atomic.AddUint64(&c.requestCounter, 1)

		log.Debugf("Request #%v: %v", reqId, url)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, nil, err
		}

		req.Header.Add("User-Agent", USER_AGENT)

		resp, err := c.httpClient.Do(req)
		if err == nil {
			log.Debugf("Response #%v status: %v %v", reqId, resp.Proto, resp.Status)

			if log.EffectiveLogLevel() <= loggo.TRACE {
				for key, values := range resp.Header {
					for _, value := range values {
						log.Tracef("%v: %v\n", key, value)
					}
				}
			}

			if log.EffectiveLogLevel() <= loggo.DEBUG {
				for key, values := range resp.Header {
					if strings.ToLower(key) == "x-message" {
						for _, value := range values {
							log.Debugf("Server message: %v\n", value)
						}
					}
				}
			}

			// Update current assessments.

			headerValue := resp.Header.Get("X-Current-Assessments")
			if headerValue != "" {
				i, err := strconv.Atoi(headerValue)
				if err == nil {
					if c.currentAssessments != i {
						c.currentAssessments = i
						log.Debugf("Server set current assessments to %v", headerValue)
					}
				} else {
					log.Warningf("Ignoring invalid X-Current-Assessments value (%v): %v", headerValue, err)
				}
			}

			// Update maximum assessments.

			headerValue = resp.Header.Get("X-Max-Assessments")
			if headerValue != "" {
				i, err := strconv.Atoi(headerValue)
				if err == nil {
					if c.maxAssessments != i {
						c.maxAssessments = i

						if c.maxAssessments <= 0 {
							return nil, nil, errors.New("Server doesn't allow further API requests")
						}

						log.Debugf("Server set maximum assessments to %v", headerValue)
					}
				} else {
					log.Warningf("Ignoring invalid X-Max-Assessments value (%v): %v", headerValue, err)
				}
			}

			// Retrieve the response body.

			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, nil, err
			}
			log.Tracef("Response #%v body:\n%v", reqId, string(body))

			return resp, body, nil
		} else {
			if strings.Contains(err.Error(), "EOF") {
				// Server closed a persistent connection on us, which
				// Go doesn't seem to be handling well. So we'll try one
				// more time.
				if retryCount > 5 {
					return nil, nil, errors.New("Too many HTTP requests (5) failed with EOF (ref#2)")
				}

				log.Debugf("HTTP request failed with EOF (ref#2)")
			} else {
				return nil, nil, errors.New(fmt.Sprintf("HTTP request failed: %v (ref#2)", err.Error()))
			}

			retryCount++
		}
	}
}

func (c *SSLLabsClient) invokeApi(command string) (*http.Response, []byte, error) {
	var url = c.apiLocation + "/" + command

	log.Tracef("Invoking API with: '%s'", url)
	for {
		resp, body, err := c.invokeGetRepeatedly(url)
		if err != nil {
			return nil, nil, err
		}

		// Status codes 429, 503, and 529 essentially mean try later. Thus,
		// if we encounter them, we sleep for a while and try again.
		if resp.StatusCode == 429 {
			return resp, body, errors.New("Assessment failed: 429")
		} else if (resp.StatusCode == 503) || (resp.StatusCode == 529) {
			// In case of the overloaded server, randomize the sleep time so
			// that some clients reconnect earlier and some later.

			sleepTime := 15 + rand.Int31n(15)

			log.Debugf("Sleeping for %v minutes after a %v response", sleepTime, resp.StatusCode)

			time.Sleep(time.Duration(sleepTime) * time.Minute)
		} else if (resp.StatusCode != 200) && (resp.StatusCode != 400) {
			return nil, nil, errors.New(fmt.Sprintf("Unexpected response status code %v", resp.StatusCode))
		} else {
			return resp, body, nil
		}
	}
}

func (c *SSLLabsClient) invokeInfo() (*LabsInfo, error) {
	var command = "info"

	_, body, err := c.invokeApi(command)
	if err != nil {
		return nil, err
	}

	var labsInfo LabsInfo
	err = json.Unmarshal(body, &labsInfo)
	if err != nil {
		log.Errorf("JSON unmarshal error: %v", err)
		return nil, err
	}

	return &labsInfo, nil
}

func (c *SSLLabsClient) invokeAnalyze(host string, startNew bool, fromCache bool) (*LabsReport, error) {
	var command = "analyze?host=" + host + "&all=done"

	if fromCache {
		command = command + "&fromCache=on"

		if c.maxAge != 0 {
			command = command + "&maxAge=" + strconv.Itoa(c.maxAge)
		}
	} else if startNew {
		command = command + "&startNew=on"
	}

	if c.ignoreMismatch {
		command = command + "&ignoreMismatch=on"
	}

	resp, body, err := c.invokeApi(command)
	if err != nil {
		return nil, err
	}

	// Use the status code to determine if the response is an error.
	if resp.StatusCode == 400 {
		// Parameter validation error.

		var apiError LabsErrorResponse
		err = json.Unmarshal(body, &apiError)
		if err != nil {
			log.Errorf("JSON unmarshal error: %v", err)
			return nil, err
		}

		return nil, apiError
	} else {
		// We should have a proper response.

		var analyzeResponse LabsReport
		err = json.Unmarshal(body, &analyzeResponse)
		if err != nil {
			log.Errorf("JSON unmarshal error: %v", err)
			return nil, err
		}

		// Add the JSON body to the response
		analyzeResponse.rawJSON = string(body)

		return &analyzeResponse, nil
	}
}
