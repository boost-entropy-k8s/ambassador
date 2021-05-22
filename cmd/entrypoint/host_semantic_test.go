package entrypoint_test

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/datawire/ambassador/cmd/entrypoint"
	bootstrap "github.com/datawire/ambassador/pkg/api/envoy/config/bootstrap/v2"
	http "github.com/datawire/ambassador/pkg/api/envoy/config/filter/network/http_connection_manager/v2"
	amb "github.com/datawire/ambassador/pkg/api/getambassador.io/v2"
	"github.com/datawire/ambassador/pkg/envoy-control-plane/resource/v2"
	"github.com/datawire/ambassador/pkg/envoy-control-plane/wellknown"
	"github.com/datawire/ambassador/pkg/kates"
	"github.com/stretchr/testify/require"
)

func jsonify(obj interface{}) string {
	bytes, err := json.MarshalIndent(obj, "", "  ")

	if err != nil {
		panic(err)
	}

	return string(bytes)
}

func loadYAML(path string) []kates.Object {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	objs, err := kates.ParseManifests(string(content))
	if err != nil {
		panic(err)
	}

	return objs
}

func strmatch(what string, text string, pattern string, regex bool) (bool, string, string) {
	var err error
	rc := false
	authority := ""
	authorityMatch := ""

	if regex {
		// The hostname is a glob, and determining if a regex and a glob match each
		// other is (possibly NP-)hard, so meh, we'll say they always match.
		rc = true
		authority = pattern
		authorityMatch = "re~"
	} else if strings.HasPrefix(pattern, "*") || strings.HasSuffix(pattern, "*") {
		// It's a supportable glob.
		globre := strings.Replace(pattern, ".", "\\.", -1)
		globre = strings.Replace(globre, "*", "[^\\.]+", -1)
		globre = "^" + globre + "$"

		rc, err = regexp.MatchString(globre, text)

		if err != nil {
			panic(err)
		}

		authority = pattern
		authorityMatch = "gl~"
	} else {
		// Nothing special, so exact match.
		rc = (pattern == text)
		authority = pattern
		authorityMatch = "=="
	}

	fmt.Printf("strmatch %s: '%s' %s '%s' == %v\n", what, text, authorityMatch, authority, rc)
	return rc, authority, authorityMatch
}

func matchesHost(mapping amb.Mapping, host amb.Host) (bool, string, string) {
	hostName := host.Spec.Hostname
	mappingHost := mapping.Spec.Host
	mappingHostRegexPtr := mapping.Spec.HostRegex
	mappingHostRegex := false

	if mappingHostRegexPtr != nil {
		mappingHostRegex = *mappingHostRegexPtr
	}

	fmt.Printf("matchesHost: hostName %s mappingHost %s\n", hostName, mappingHost)

	if mappingHost != "" {
		return strmatch("Host", hostName, mappingHost, mappingHostRegex)
	}

	// No host in the Mapping -- how about authority?
	mappingAuthorityRegex := false
	mappingAuthorityBoolOrString, found := mapping.Spec.Headers[":authority"]
	mappingAuthority := ""

	if found && (mappingAuthorityBoolOrString.String != nil) {
		mappingAuthority = *mappingAuthorityBoolOrString.String
	} else {
		// Try a regex authority.
		mappingAuthorityBoolOrString, found = mapping.Spec.RegexHeaders[":authority"]

		if found && (mappingAuthorityBoolOrString.String != nil) {
			mappingAuthorityRegex = true
			mappingAuthority = *mappingAuthorityBoolOrString.String
		}
	}

	fmt.Printf("matchesHost: mappingAuthority %s\n", mappingAuthority)

	if mappingAuthority != "" {
		return strmatch("Authority", hostName, mappingAuthority, mappingAuthorityRegex)
	}

	fmt.Printf("matchesHost: fallthrough\n")
	// If we're here, there's no host to match, so return true.
	return true, "", ""
}

type RenderedRoute struct {
	Scheme         string `json:"scheme"`
	Host           string `json:"host"`
	Path           string `json:"path"`
	Authority      string `json:"authority"`
	AuthorityMatch string `json:"authorityMatch"`
	Action         string `json:"action"`
	ActionArg      string `json:"action_arg"`
}

func (rr *RenderedRoute) String() string {
	s := fmt.Sprintf("%s%s: %s://%s%s", rr.Action, rr.ActionArg, rr.Scheme, rr.Host, rr.Path)

	if rr.Authority != "" {
		s += fmt.Sprintf(" (:authority %s %s)", rr.AuthorityMatch, rr.Authority)
	}

	return s
}

type RenderedVHost struct {
	Name   string          `json:"name"`
	Routes []RenderedRoute `json:"routes"`
}

func (rvh *RenderedVHost) addRoute(rr RenderedRoute) {
	rvh.Routes = append(rvh.Routes, rr)
}

func newRenderedVHost(name string) RenderedVHost {
	return RenderedVHost{
		Name:   name,
		Routes: []RenderedRoute{},
	}
}

type RenderedChain struct {
	ServerNames       []string                  `json:"server_names"`
	TransportProtocol string                    `json:"transport_protocol"`
	VHosts            map[string]*RenderedVHost `json:"-"`
	VHostList         []*RenderedVHost          `json:"vhosts"`
}

func (rchain *RenderedChain) addVHost(rvh *RenderedVHost) {
	rchain.VHosts[rvh.Name] = rvh
}

func (rchain *RenderedChain) getVHost(vhostname string) *RenderedVHost {
	return rchain.VHosts[vhostname]
}

func newRenderedChain(serverNames []string, transportProtocol string) RenderedChain {
	return RenderedChain{
		ServerNames:       serverNames,
		TransportProtocol: transportProtocol,
		VHosts:            map[string]*RenderedVHost{},
		VHostList:         []*RenderedVHost{},
	}
}

type RenderedListener struct {
	Name      string                    `json:"name"`
	Port      uint32                    `json:"port"`
	Chains    map[string]*RenderedChain `json:"-"`
	ChainList []*RenderedChain          `json:"chains"`
}

func (rl *RenderedListener) addChain(rchain *RenderedChain) {
	hostname := "*"

	if len(rchain.ServerNames) > 0 {
		hostname = rchain.ServerNames[0]
	}

	xport := rchain.TransportProtocol

	extant := rl.getChain(hostname, xport)

	if extant != nil {
		panic(fmt.Errorf("chain for %s, %s already exists in %s", hostname, xport, rl.Name))
	}

	key := fmt.Sprintf("%s-%s", hostname, xport)

	rl.Chains[key] = rchain
}

func (rl *RenderedListener) getChain(hostname string, xport string) *RenderedChain {
	key := fmt.Sprintf("%s-%s", hostname, xport)

	return rl.Chains[key]
}

func newRenderedListener(name string, port uint32) RenderedListener {
	return RenderedListener{
		Name:      name,
		Port:      port,
		Chains:    map[string]*RenderedChain{},
		ChainList: []*RenderedChain{},
	}
}

func newAmbassadorListener(port uint32) RenderedListener {
	return RenderedListener{
		Name:   fmt.Sprintf("ambassador-listener-0.0.0.0-%d", port),
		Port:   port,
		Chains: map[string]*RenderedChain{},
	}
}

func newAmbassadorMapping(name string, pfx string) amb.Mapping {
	return amb.Mapping{
		TypeMeta:   kates.TypeMeta{Kind: "Mapping"},
		ObjectMeta: kates.ObjectMeta{Namespace: "default", Name: name},
		Spec: amb.MappingSpec{
			Prefix:  pfx,
			Service: "127.0.0.1:8877",
		},
	}
}

func jsonifyRenderedListeners(renderedListeners []RenderedListener) string {
	// Why is this needed? JSONifying renderedListeners directly always
	// shows empty listeners -- kinda feels like something's getting copied
	// in a way I'm not awake enough to follow right now.
	toDump := []RenderedListener{}

	for _, l := range renderedListeners {
		for _, c := range l.Chains {
			for _, v := range c.VHosts {
				sort.SliceStable(v.Routes, func(i, j int) bool {
					if v.Routes[i].Path != v.Routes[j].Path {
						return v.Routes[i].Path < v.Routes[j].Path
					}

					if v.Routes[i].Host != v.Routes[j].Host {
						return v.Routes[i].Host < v.Routes[j].Host
					}

					if v.Routes[i].Action != v.Routes[j].Action {
						return v.Routes[i].Action < v.Routes[j].Action
					}

					return v.Routes[i].ActionArg < v.Routes[j].ActionArg
				})

				c.VHostList = append(c.VHostList, v)
			}

			sort.SliceStable(c.VHostList, func(i, j int) bool {
				return c.VHostList[i].Name < c.VHostList[j].Name
			})

			l.ChainList = append(l.ChainList, c)
		}

		sort.SliceStable(l.ChainList, func(i, j int) bool {
			if l.ChainList[i].ServerNames[0] != l.ChainList[j].ServerNames[0] {
				return l.ChainList[i].ServerNames[0] < l.ChainList[j].ServerNames[0]
			}

			return l.ChainList[i].TransportProtocol < l.ChainList[j].TransportProtocol
		})

		toDump = append(toDump, l)
	}

	sort.SliceStable(toDump, func(i, j int) bool {
		return toDump[i].Port < toDump[j].Port
	})

	return jsonify(toDump)
}

type Candidate struct {
	Scheme    string
	Action    string
	ActionArg string
}

func TestHostSemantics(t *testing.T) {
	f := entrypoint.RunFake(t, entrypoint.FakeConfig{EnvoyConfig: true, DiagdDebug: false}, nil)

	// Figure out all the clusters we'll need.
	needClusters := []string{}

	mappingObjects := loadYAML("testdata/ffs-mappings.yaml")
	hostObjects := loadYAML("testdata/ffs-hosts.yaml")

	// expectedListeners is what we think we're going to get.
	expectedListeners := []RenderedListener{
		newAmbassadorListener(8080),
		newAmbassadorListener(8443),
	}

	// Initialize our mappings with the Ambassador mappings...
	allMappings := []amb.Mapping{
		newAmbassadorMapping("ambassador-check-ready", "/ambassador/v0/check_ready"),
		newAmbassadorMapping("ambassador-check-alive", "/ambassador/v0/check_alive"),
		newAmbassadorMapping("ambassador-v0", "/ambassador/v0/"),
	}

	// ...then copy in everything we just read.
	for _, obj := range mappingObjects {
		mapping, ok := obj.(*amb.Mapping)

		if ok {
			allMappings = append(allMappings, *mapping)
		}
	}

	clusterRE := regexp.MustCompile("[^0-9A-Za-z_]")

	for _, mapping := range allMappings {
		fmt.Printf("CHECK Mapping %s\n%s\n", mapping.Name, jsonify(mapping))

		// Grab the cluster name, and remember it for later.
		mangledService := clusterRE.ReplaceAll([]byte(mapping.Spec.Service), []byte("_"))
		clusterName := fmt.Sprintf("cluster_%s_default", mangledService)
		needClusters = append(needClusters, clusterName)

		// Next, go figure out which hosts this mapping matches.
		for _, obj := range hostObjects {
			host, ok := obj.(*amb.Host)

			if !ok {
				// Secret or TLSContext
				continue
			}

			// Does this Mapping match this host?
			hostmatch, authority, authorityMatch := matchesHost(mapping, *host)

			if hostmatch {
				mappingName := mapping.Name
				hostName := host.Name
				hostRequestPolicy := host.Spec.RequestPolicy
				hostInsecureAction := "REDIRECT"

				if hostRequestPolicy != nil {
					hostInsecureAction := strings.ToUpper(hostRequestPolicy.Insecure.Action)

					if hostInsecureAction == "" {
						hostInsecureAction = "REDIRECT"
					}
				}

				fmt.Printf("Mapping %s matches %s (%s)\n", mappingName, hostName, hostInsecureAction)
				// fmt.Printf(yaml.safe_dump_all([ mapping.config, host.config ]))

				// Yes, this is as horrible and hacky as it looks, but it's a good way to have two
				// different sets of logic trying to compute the same thing.

				insecureActionArg := ""

				if hostInsecureAction == "ROUTE" {
					insecureActionArg = " " + clusterName
				} else if hostInsecureAction == "REDIRECT" {
					insecureActionArg = " HTTPS"
				}

				for _, l := range expectedListeners {
					candidates := []Candidate{
						Candidate{
							Scheme:    "https",
							Action:    "ROUTE",
							ActionArg: " " + clusterName,
						},
					}

					if hostInsecureAction != "REJECT" {
						candidates = append(candidates,
							Candidate{
								Scheme:    "http",
								Action:    hostInsecureAction,
								ActionArg: insecureActionArg,
							},
						)
					}

					for _, candidate := range candidates {
						// XXX
						xport := ""

						if host.Spec.TLSSecret != nil {
							xport = "tls"
						}

						// Is the hostname for this Host in our chains?
						chain := l.getChain(hostName, xport)

						if chain == nil {
							// Nope, make a new one.
							newChain := newRenderedChain([]string{hostName}, xport)
							chain = &newChain
							l.addChain(chain)
						}

						vhostName := fmt.Sprintf("%s-%s", l.Name, hostName)
						vhost := chain.getVHost(vhostName)

						if vhost == nil {
							newVHost := newRenderedVHost(vhostName)
							vhost = &newVHost
							chain.addVHost(vhost)
						}

						vhost.addRoute(RenderedRoute{
							Scheme:         candidate.Scheme,
							Host:           hostName,
							Path:           mapping.Spec.Prefix,
							Authority:      authority,
							AuthorityMatch: authorityMatch,
							Action:         candidate.Action,
							ActionArg:      candidate.ActionArg,
						})
					}
				}
			}
		}
	}

	expectedJSON := jsonifyRenderedListeners(expectedListeners)

	f.UpsertFile("testdata/ffs-hosts.yaml")
	f.UpsertFile("testdata/ffs-mappings.yaml")
	f.Flush()

	// snap := f.GetSnapshot(HasMapping("default", "mapping-ehmnax-wild-axtsin"))
	snap := f.GetSnapshot(HasMapping("default", "test-mapping"))

	fmt.Printf("GOT SNAP\n")

	require.NotNil(t, snap)

	envoyConfig := f.GetEnvoyConfig(func(config *bootstrap.Bootstrap) bool {
		for _, cluster := range needClusters {
			if FindCluster(config, ClusterNameContains(cluster)) == nil {
				return false
			}
		}

		return true
	})

	require.NotNil(t, envoyConfig)

	totalRoutes := 0
	goodRoutes := 0
	badRoutes := 0

	renderedListeners := make([]RenderedListener, 0, 2)

	for _, l := range envoyConfig.StaticResources.Listeners {
		port := l.Address.GetSocketAddress().GetPortValue()

		fmt.Printf("LISTENER %s on port %d (chains %d)\n", l.Name, port, len(l.FilterChains))
		rlistener := newRenderedListener(l.Name, port)

		for _, chain := range l.FilterChains {
			fmt.Printf("  CHAIN %s\n", chain.FilterChainMatch)

			rchain := newRenderedChain(chain.FilterChainMatch.ServerNames, chain.FilterChainMatch.TransportProtocol)

			for _, filter := range chain.Filters {
				if filter.Name != wellknown.HTTPConnectionManager {
					// We only know how to create an rds listener for HttpConnectionManager
					// listeners. We must ignore all other listeners.
					continue
				}

				// Note that the hcm configuration is stored in a protobuf any, so make
				// sure that GetHTTPConnectionManager is actually returning an unmarshalled copy.
				hcm := resource.GetHTTPConnectionManager(filter)
				if hcm == nil {
					continue
				}

				// RouteSpecifier is a protobuf oneof that corresponds to the rds, route_config, and
				// scoped_routes fields. Only one of those may be set at a time.
				rs, ok := hcm.RouteSpecifier.(*http.HttpConnectionManager_RouteConfig)
				if !ok {
					continue
				}

				rc := rs.RouteConfig

				for _, vhost := range rc.VirtualHosts {
					fmt.Printf("    VHost %s\n", vhost.Name)

					rvh := newRenderedVHost(vhost.Name)

					for _, domain := range vhost.Domains {
						for _, route := range vhost.Routes {
							m := route.Match
							pfx := m.GetPrefix()
							hdrs := m.GetHeaders()
							scheme := "implicit-http"

							if !strings.HasPrefix(pfx, "/") {
								pfx = "/" + pfx
							}

							authority := ""
							authorityMatch := ""

							for _, h := range hdrs {
								hName := h.Name
								prefixMatch := h.GetPrefixMatch()
								suffixMatch := h.GetSuffixMatch()
								exactMatch := h.GetExactMatch()

								regexMatch := ""
								srm := h.GetSafeRegexMatch()

								if srm != nil {
									regexMatch = srm.Regex
								} else {
									regexMatch = h.GetRegexMatch()
								}

								// summary := fmt.Sprintf("%#v", h)

								if exactMatch != "" {
									if hName == "x-forwarded-proto" {
										scheme = exactMatch
										continue
									}

									authority = exactMatch
									authorityMatch = "=="
								} else if prefixMatch != "" {
									authority = prefixMatch + "*"
									authorityMatch = "gl~"
								} else if suffixMatch != "" {
									authority = "*" + suffixMatch
									authorityMatch = "gl~"
								} else if regexMatch != "" {
									authority = regexMatch
									authorityMatch = "re~"
								}
							}

							// // Assume we don't know WTF we want here.
							// expectedAction := "PANIC"

							// // If it's a secure request, always route.
							// if scheme == "https" {
							// 	expectedAction = "ROUTE"
							// } else {
							// 	// The prefix cleverly encodes the expected action.
							// 	if strings.HasSuffix(pfx, "-route/") {
							// 		expectedAction = "ROUTE"
							// 	} else if strings.HasSuffix(pfx, "-redirect/") {
							// 		expectedAction = "REDIRECT"
							// 	} else if strings.HasSuffix(pfx, "-noaction/") {
							// 		// This is the case where no insecure action is given, which means
							// 		// it defaults to Redirect.
							// 		expectedAction = "REDIRECT"
							// 	} else {
							// 		// This isn't good enough, since rejected routes will just not appear.
							// 		expectedAction = "REJECT"
							// 	}
							// }

							actionRoute := route.GetRoute()
							actionRedirect := route.GetRedirect()

							finalAction := "???"
							finalActionArg := ""

							if actionRoute != nil {
								finalAction = "ROUTE"
								finalActionArg = " " + actionRoute.GetCluster()
							} else if actionRedirect != nil {
								finalAction = "REDIRECT"

								if actionRedirect.GetHttpsRedirect() {
									finalActionArg = " HTTPS"
								} else {
									finalActionArg = fmt.Sprintf(" %#v", actionRedirect)
								}
							}

							rroute := RenderedRoute{
								Scheme:         scheme,
								Host:           domain,
								Path:           pfx,
								Authority:      authority,
								AuthorityMatch: authorityMatch,
								Action:         finalAction,
								ActionArg:      finalActionArg,
							}

							rvh.addRoute(rroute)

							fmt.Printf("      %s\n", rroute.String())
							totalRoutes++

							// if expectedAction != finalAction {
							// 	fmt.Printf("    !! wanted %s\n", expectedAction)
							// 	badRoutes++
							// } else {
							// 	goodRoutes++
							// }
							// require.Equal(t, expectedAction, finalAction)
						}
					}

					rchain.addVHost(&rvh)
				}
			}

			rlistener.addChain(&rchain)
		}

		renderedListeners = append(renderedListeners, rlistener)
	}

	actualJSON := jsonifyRenderedListeners(renderedListeners)

	err := ioutil.WriteFile("/tmp/host-semantics-expected.json", []byte(expectedJSON), 0644)
	if err == io.EOF {
		err = nil
	}
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile("/tmp/host-semantics-actual.json", []byte(actualJSON), 0644)
	if err == io.EOF {
		err = nil
	}
	if err != nil {
		panic(err)
	}

	require.Equal(t, expectedJSON, actualJSON, "Mismatch!")

	fmt.Printf("Total routes: %d -- good %d, bad %d\n", totalRoutes, goodRoutes, badRoutes)
}
