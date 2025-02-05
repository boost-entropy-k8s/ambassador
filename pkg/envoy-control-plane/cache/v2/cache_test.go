package cache_test

import (
	"testing"

	discovery "github.com/datawire/ambassador/v2/pkg/api/envoy/api/v2"
	route "github.com/datawire/ambassador/v2/pkg/api/envoy/api/v2"
	"github.com/datawire/ambassador/v2/pkg/envoy-control-plane/cache/types"
	"github.com/datawire/ambassador/v2/pkg/envoy-control-plane/cache/v2"
	"github.com/datawire/ambassador/v2/pkg/envoy-control-plane/resource/v2"
	ttl_helper "github.com/datawire/ambassador/v2/pkg/envoy-control-plane/ttl/v2"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/stretchr/testify/assert"
)

const (
	resourceName = "route1"
)

func TestResponseGetDiscoveryResponse(t *testing.T) {
	routes := []types.ResourceWithTtl{{Resource: &route.RouteConfiguration{Name: resourceName}}}
	resp := cache.RawResponse{
		Request:   &discovery.DiscoveryRequest{TypeUrl: resource.RouteType},
		Version:   "v",
		Resources: routes,
	}

	discoveryResponse, err := resp.GetDiscoveryResponse()
	assert.Nil(t, err)
	assert.Equal(t, discoveryResponse.VersionInfo, resp.Version)
	assert.Equal(t, len(discoveryResponse.Resources), 1)

	cachedResponse, err := resp.GetDiscoveryResponse()
	assert.Nil(t, err)
	assert.Same(t, discoveryResponse, cachedResponse)

	r := &route.RouteConfiguration{}
	err = ptypes.UnmarshalAny(discoveryResponse.Resources[0], r)
	assert.Nil(t, err)
	assert.Equal(t, r.Name, resourceName)
}

func TestPassthroughResponseGetDiscoveryResponse(t *testing.T) {
	routes := []types.Resource{&route.RouteConfiguration{Name: resourceName}}
	rsrc, err := ptypes.MarshalAny(routes[0])
	assert.Nil(t, err)
	dr := &discovery.DiscoveryResponse{
		TypeUrl:     resource.RouteType,
		Resources:   []*any.Any{rsrc},
		VersionInfo: "v",
	}
	resp := cache.PassthroughResponse{
		Request:           &discovery.DiscoveryRequest{TypeUrl: resource.RouteType},
		DiscoveryResponse: dr,
	}

	discoveryResponse, err := resp.GetDiscoveryResponse()
	assert.Nil(t, err)
	assert.Equal(t, discoveryResponse.VersionInfo, resp.DiscoveryResponse.VersionInfo)
	assert.Equal(t, len(discoveryResponse.Resources), 1)

	r := &route.RouteConfiguration{}
	err = ptypes.UnmarshalAny(discoveryResponse.Resources[0], r)
	assert.Nil(t, err)
	assert.Equal(t, r.Name, resourceName)
	assert.Equal(t, discoveryResponse, dr)
}

func TestHeartbeatResponseGetDiscoveryResponse(t *testing.T) {
	routes := []types.ResourceWithTtl{{Resource: &route.RouteConfiguration{Name: resourceName}}}
	resp := cache.RawResponse{
		Request:   &discovery.DiscoveryRequest{TypeUrl: resource.RouteType},
		Version:   "v",
		Resources: routes,
		Heartbeat: true,
	}

	discoveryResponse, err := resp.GetDiscoveryResponse()
	assert.Nil(t, err)
	assert.Equal(t, discoveryResponse.VersionInfo, resp.Version)
	assert.Equal(t, len(discoveryResponse.Resources), 1)
	assert.True(t, ttl_helper.IsTTLResource(discoveryResponse.Resources[0]))

	cachedResponse, err := resp.GetDiscoveryResponse()
	assert.Nil(t, err)
	assert.Same(t, discoveryResponse, cachedResponse)

	r := &route.RouteConfiguration{}
	err = ptypes.UnmarshalAny(discoveryResponse.Resources[0], r)
	assert.Nil(t, err)
	assert.Equal(t, r.Name, resourceName)
}
