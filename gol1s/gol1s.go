/* Open Traffic Generator L1S(Layer1Switch) Model API 0.0.1
 * OTG L1S(Layer1Switch) Model
 * License: MIT */

package gol1s

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/ghodss/yaml"
	l1s_pb "github.com/open-traffic-generator/openl1s/gol1s/l1s_pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// function related to error handling
func FromError(err error) (Error, bool) {
	if rErr, ok := err.(Error); ok {
		return rErr, true
	}

	rErr := NewError()
	if err := rErr.Unmarshal().FromJson(err.Error()); err == nil {
		return rErr, true
	}

	return fromGrpcError(err)
}

func setResponseErr(obj Error, code int32, message string) {
	errors := []string{}
	errors = append(errors, message)
	obj.msg().Code = &code
	obj.msg().Errors = errors
}

// parses and return errors for grpc response
func fromGrpcError(err error) (Error, bool) {
	st, ok := status.FromError(err)
	if ok {
		rErr := NewError()
		if err := rErr.Unmarshal().FromJson(st.Message()); err == nil {
			var code = int32(st.Code())
			rErr.msg().Code = &code
			return rErr, true
		}

		setResponseErr(rErr, int32(st.Code()), st.Message())
		return rErr, true
	}

	return nil, false
}

// parses and return errors for http responses
func fromHttpError(statusCode int, body []byte) Error {
	rErr := NewError()
	bStr := string(body)
	if err := rErr.Unmarshal().FromJson(bStr); err == nil {
		return rErr
	}

	setResponseErr(rErr, int32(statusCode), bStr)

	return rErr
}

type versionMeta struct {
	checkVersion  bool
	localVersion  Version
	remoteVersion Version
	checkError    error
}
type gol1SApi struct {
	apiSt
	grpcClient  l1s_pb.OpenapiClient
	httpClient  httpClient
	versionMeta *versionMeta
}

// grpcConnect builds up a grpc connection
func (api *gol1SApi) grpcConnect() error {
	if api.grpcClient == nil {
		if api.grpc.clientConnection == nil {
			ctx, cancelFunc := context.WithTimeout(context.Background(), api.grpc.dialTimeout)
			defer cancelFunc()
			conn, err := grpc.DialContext(ctx, api.grpc.location, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				return err
			}
			api.grpcClient = l1s_pb.NewOpenapiClient(conn)
			api.grpc.clientConnection = conn
		} else {
			api.grpcClient = l1s_pb.NewOpenapiClient(api.grpc.clientConnection)
		}
	}
	return nil
}

func (api *gol1SApi) grpcClose() error {
	if api.grpc != nil {
		if api.grpc.clientConnection != nil {
			err := api.grpc.clientConnection.Close()
			if err != nil {
				return err
			}
		}
	}
	api.grpcClient = nil
	api.grpc = nil
	return nil
}

func (api *gol1SApi) Close() error {
	if api.hasGrpcTransport() {
		err := api.grpcClose()
		return err
	}
	if api.hasHttpTransport() {
		err := api.http.conn.(*net.TCPConn).SetLinger(0)
		api.http.conn.Close()
		api.http.conn = nil
		api.http = nil
		api.httpClient.client = nil
		return err
	}
	return nil
}

// NewApi returns a new instance of the top level interface hierarchy
func NewApi() Api {
	api := gol1SApi{}
	api.versionMeta = &versionMeta{checkVersion: false}
	return &api
}

// httpConnect builds up a http connection
func (api *gol1SApi) httpConnect() error {
	if api.httpClient.client == nil {
		tr := http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				tcpConn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(tcpConn, &tls.Config{InsecureSkipVerify: !api.http.verify})
				err = tlsConn.Handshake()
				if err != nil {
					return nil, err
				}
				api.http.conn = tcpConn
				return tlsConn, nil
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				tcpConn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				api.http.conn = tcpConn
				return tcpConn, nil
			},
		}
		client := httpClient{
			client: &http.Client{
				Transport: &tr,
			},
			ctx: context.Background(),
		}
		api.httpClient = client
	}
	return nil
}

func (api *gol1SApi) httpSendRecv(urlPath string, jsonBody string, method string) (*http.Response, error) {
	err := api.httpConnect()
	if err != nil {
		return nil, err
	}
	httpClient := api.httpClient
	var bodyReader = bytes.NewReader([]byte(jsonBody))
	queryUrl, err := url.Parse(api.http.location)
	if err != nil {
		return nil, err
	}
	queryUrl, _ = queryUrl.Parse(urlPath)
	req, _ := http.NewRequest(method, queryUrl.String(), bodyReader)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(httpClient.ctx)
	response, err := httpClient.client.Do(req)
	return response, err
}

// Gol1SApi oTG L1S(Layer1Switch) Model
type Api interface {
	api
	// SetConfig create configuration for L1S
	SetConfig(config Config) (*string, error)
	// GetVersion description is TBD
	GetVersion() (Version, error)
	// GetLocalVersion provides version details of local client
	GetLocalVersion() Version
	// GetRemoteVersion provides version details received from remote server
	GetRemoteVersion() (Version, error)
	// SetVersionCompatibilityCheck allows enabling or disabling automatic version
	// compatibility check between client and server API spec version upon API call
	SetVersionCompatibilityCheck(bool)
	// CheckVersionCompatibility compares API spec version for local client and remote server,
	// and returns an error if they are not compatible according to Semantic Versioning 2.0.0
	CheckVersionCompatibility() error
}

func (api *gol1SApi) GetLocalVersion() Version {
	if api.versionMeta.localVersion == nil {
		api.versionMeta.localVersion = NewVersion().SetApiSpecVersion("0.0.1").SetSdkVersion("0.0.1")
	}

	return api.versionMeta.localVersion
}

func (api *gol1SApi) GetRemoteVersion() (Version, error) {
	if api.versionMeta.remoteVersion == nil {
		v, err := api.GetVersion()
		if err != nil {
			return nil, fmt.Errorf("could not fetch remote version: %v", err)
		}

		api.versionMeta.remoteVersion = v
	}

	return api.versionMeta.remoteVersion, nil
}

func (api *gol1SApi) SetVersionCompatibilityCheck(v bool) {
	api.versionMeta.checkVersion = v
}

func (api *gol1SApi) checkLocalRemoteVersionCompatibility() (error, error) {
	localVer := api.GetLocalVersion()
	remoteVer, err := api.GetRemoteVersion()
	if err != nil {
		return nil, err
	}
	err = checkClientServerVersionCompatibility(localVer.ApiSpecVersion(), remoteVer.ApiSpecVersion(), "API spec")
	if err != nil {
		return fmt.Errorf(
			"client SDK version '%s' is not compatible with server SDK version '%s': %v",
			localVer.SdkVersion(), remoteVer.SdkVersion(), err,
		), nil
	}

	return nil, nil
}

func (api *gol1SApi) checkLocalRemoteVersionCompatibilityOnce() error {
	if !api.versionMeta.checkVersion {
		return nil
	}

	if api.versionMeta.checkError != nil {
		return api.versionMeta.checkError
	}

	compatErr, apiErr := api.checkLocalRemoteVersionCompatibility()
	if compatErr != nil {
		api.versionMeta.checkError = compatErr
		return compatErr
	}
	if apiErr != nil {
		api.versionMeta.checkError = nil
		return apiErr
	}

	api.versionMeta.checkVersion = false
	api.versionMeta.checkError = nil
	return nil
}

func (api *gol1SApi) CheckVersionCompatibility() error {
	compatErr, apiErr := api.checkLocalRemoteVersionCompatibility()
	if compatErr != nil {
		return fmt.Errorf("version error: %v", compatErr)
	}
	if apiErr != nil {
		return apiErr
	}

	return nil
}

func (api *gol1SApi) SetConfig(config Config) (*string, error) {

	if err := config.validate(); err != nil {
		return nil, err
	}

	if err := api.checkLocalRemoteVersionCompatibilityOnce(); err != nil {
		return nil, err
	}
	if api.hasHttpTransport() {
		return api.httpSetConfig(config)
	}
	if err := api.grpcConnect(); err != nil {
		return nil, err
	}
	request := l1s_pb.SetConfigRequest{Config: config.msg()}
	ctx, cancelFunc := context.WithTimeout(context.Background(), api.grpc.requestTimeout)
	defer cancelFunc()
	resp, err := api.grpcClient.SetConfig(ctx, &request)
	if err != nil {
		if er, ok := fromGrpcError(err); ok {
			return nil, er
		}
		return nil, err
	}
	if resp.GetString_() != "" {
		status_code_value := resp.GetString_()
		return &status_code_value, nil
	}
	return nil, nil
}

func (api *gol1SApi) GetVersion() (Version, error) {

	if api.hasHttpTransport() {
		return api.httpGetVersion()
	}
	if err := api.grpcConnect(); err != nil {
		return nil, err
	}
	request := emptypb.Empty{}
	ctx, cancelFunc := context.WithTimeout(context.Background(), api.grpc.requestTimeout)
	defer cancelFunc()
	resp, err := api.grpcClient.GetVersion(ctx, &request)
	if err != nil {
		if er, ok := fromGrpcError(err); ok {
			return nil, er
		}
		return nil, err
	}
	ret := NewVersion()
	if resp.GetVersion() != nil {
		return ret.setMsg(resp.GetVersion()), nil
	}

	return ret, nil
}

func (api *gol1SApi) httpSetConfig(config Config) (*string, error) {
	configJson, err := config.Marshal().ToJson()
	if err != nil {
		return nil, err
	}
	resp, err := api.httpSendRecv("config", configJson, "POST")

	if err != nil {
		return nil, err
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 200 {
		bodyString := string(bodyBytes)
		return &bodyString, nil
	} else {
		return nil, fromHttpError(resp.StatusCode, bodyBytes)
	}
}

func (api *gol1SApi) httpGetVersion() (Version, error) {
	resp, err := api.httpSendRecv("capabilities/version", "", "GET")
	if err != nil {
		return nil, err
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 200 {
		obj := NewGetVersionResponse().Version()
		if err := obj.Unmarshal().FromJson(string(bodyBytes)); err != nil {
			return nil, err
		}
		return obj, nil
	} else {
		return nil, fromHttpError(resp.StatusCode, bodyBytes)
	}
}

// ***** Config *****
type config struct {
	validation
	obj          *l1s_pb.Config
	marshaller   marshalConfig
	unMarshaller unMarshalConfig
	linksHolder  ConfigLinkIter
}

func NewConfig() Config {
	obj := config{obj: &l1s_pb.Config{}}
	obj.setDefault()
	return &obj
}

func (obj *config) msg() *l1s_pb.Config {
	return obj.obj
}

func (obj *config) setMsg(msg *l1s_pb.Config) Config {
	obj.setNil()
	proto.Merge(obj.obj, msg)
	return obj
}

type marshalconfig struct {
	obj *config
}

type marshalConfig interface {
	// ToProto marshals Config to protobuf object *l1s_pb.Config
	ToProto() (*l1s_pb.Config, error)
	// ToPbText marshals Config to protobuf text
	ToPbText() (string, error)
	// ToYaml marshals Config to YAML text
	ToYaml() (string, error)
	// ToJson marshals Config to JSON text
	ToJson() (string, error)
}

type unMarshalconfig struct {
	obj *config
}

type unMarshalConfig interface {
	// FromProto unmarshals Config from protobuf object *l1s_pb.Config
	FromProto(msg *l1s_pb.Config) (Config, error)
	// FromPbText unmarshals Config from protobuf text
	FromPbText(value string) error
	// FromYaml unmarshals Config from YAML text
	FromYaml(value string) error
	// FromJson unmarshals Config from JSON text
	FromJson(value string) error
}

func (obj *config) Marshal() marshalConfig {
	if obj.marshaller == nil {
		obj.marshaller = &marshalconfig{obj: obj}
	}
	return obj.marshaller
}

func (obj *config) Unmarshal() unMarshalConfig {
	if obj.unMarshaller == nil {
		obj.unMarshaller = &unMarshalconfig{obj: obj}
	}
	return obj.unMarshaller
}

func (m *marshalconfig) ToProto() (*l1s_pb.Config, error) {
	err := m.obj.validateToAndFrom()
	if err != nil {
		return nil, err
	}
	return m.obj.msg(), nil
}

func (m *unMarshalconfig) FromProto(msg *l1s_pb.Config) (Config, error) {
	newObj := m.obj.setMsg(msg)
	err := newObj.validateToAndFrom()
	if err != nil {
		return nil, err
	}
	return newObj, nil
}

func (m *marshalconfig) ToPbText() (string, error) {
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return "", vErr
	}
	protoMarshal, err := proto.Marshal(m.obj.msg())
	if err != nil {
		return "", err
	}
	return string(protoMarshal), nil
}

func (m *unMarshalconfig) FromPbText(value string) error {
	retObj := proto.Unmarshal([]byte(value), m.obj.msg())
	if retObj != nil {
		return retObj
	}
	m.obj.setNil()
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return vErr
	}
	return retObj
}

func (m *marshalconfig) ToYaml() (string, error) {
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return "", vErr
	}
	opts := protojson.MarshalOptions{
		UseProtoNames:   true,
		AllowPartial:    true,
		EmitUnpopulated: false,
	}
	data, err := opts.Marshal(m.obj.msg())
	if err != nil {
		return "", err
	}
	data, err = yaml.JSONToYAML(data)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (m *unMarshalconfig) FromYaml(value string) error {
	if value == "" {
		value = "{}"
	}
	data, err := yaml.YAMLToJSON([]byte(value))
	if err != nil {
		return err
	}
	opts := protojson.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: false,
	}
	uError := opts.Unmarshal([]byte(data), m.obj.msg())
	if uError != nil {
		return fmt.Errorf("unmarshal error %s", strings.Replace(
			uError.Error(), "\u00a0", " ", -1)[7:])
	}
	m.obj.setNil()
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return vErr
	}
	return nil
}

func (m *marshalconfig) ToJson() (string, error) {
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return "", vErr
	}
	opts := protojson.MarshalOptions{
		UseProtoNames:   true,
		AllowPartial:    true,
		EmitUnpopulated: false,
		Indent:          "  ",
	}
	data, err := opts.Marshal(m.obj.msg())
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (m *unMarshalconfig) FromJson(value string) error {
	opts := protojson.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: false,
	}
	if value == "" {
		value = "{}"
	}
	uError := opts.Unmarshal([]byte(value), m.obj.msg())
	if uError != nil {
		return fmt.Errorf("unmarshal error %s", strings.Replace(
			uError.Error(), "\u00a0", " ", -1)[7:])
	}
	m.obj.setNil()
	err := m.obj.validateToAndFrom()
	if err != nil {
		return err
	}
	return nil
}

func (obj *config) validateToAndFrom() error {
	// emptyVars()
	obj.validateObj(&obj.validation, true)
	return obj.validationResult()
}

func (obj *config) validate() error {
	// emptyVars()
	obj.validateObj(&obj.validation, false)
	return obj.validationResult()
}

func (obj *config) String() string {
	str, err := obj.Marshal().ToYaml()
	if err != nil {
		return err.Error()
	}
	return str
}

func (obj *config) Clone() (Config, error) {
	vErr := obj.validate()
	if vErr != nil {
		return nil, vErr
	}
	newObj := NewConfig()
	data, err := proto.Marshal(obj.msg())
	if err != nil {
		return nil, err
	}
	pbErr := proto.Unmarshal(data, newObj.msg())
	if pbErr != nil {
		return nil, pbErr
	}
	return newObj, nil
}

func (obj *config) setNil() {
	obj.linksHolder = nil
	obj.validationErrors = nil
	obj.warnings = nil
	obj.constraints = make(map[string]map[string]Constraints)
}

// Config is a container for L1S configuration.
type Config interface {
	Validation
	// msg marshals Config to protobuf object *l1s_pb.Config
	// and doesn't set defaults
	msg() *l1s_pb.Config
	// setMsg unmarshals Config from protobuf object *l1s_pb.Config
	// and doesn't set defaults
	setMsg(*l1s_pb.Config) Config
	// provides marshal interface
	Marshal() marshalConfig
	// provides unmarshal interface
	Unmarshal() unMarshalConfig
	// validate validates Config
	validate() error
	// A stringer function
	String() string
	// Clones the object
	Clone() (Config, error)
	validateToAndFrom() error
	validateObj(vObj *validation, set_default bool)
	setDefault()
	// Links returns ConfigLinkIterIter, set in Config
	Links() ConfigLinkIter
	setNil()
}

// Connection between ports within a switch.
// Links returns a []Link
func (obj *config) Links() ConfigLinkIter {
	if len(obj.obj.Links) == 0 {
		obj.obj.Links = []*l1s_pb.Link{}
	}
	if obj.linksHolder == nil {
		obj.linksHolder = newConfigLinkIter(&obj.obj.Links).setMsg(obj)
	}
	return obj.linksHolder
}

type configLinkIter struct {
	obj       *config
	linkSlice []Link
	fieldPtr  *[]*l1s_pb.Link
}

func newConfigLinkIter(ptr *[]*l1s_pb.Link) ConfigLinkIter {
	return &configLinkIter{fieldPtr: ptr}
}

type ConfigLinkIter interface {
	setMsg(*config) ConfigLinkIter
	Items() []Link
	Add() Link
	Append(items ...Link) ConfigLinkIter
	Set(index int, newObj Link) ConfigLinkIter
	Clear() ConfigLinkIter
	clearHolderSlice() ConfigLinkIter
	appendHolderSlice(item Link) ConfigLinkIter
}

func (obj *configLinkIter) setMsg(msg *config) ConfigLinkIter {
	obj.clearHolderSlice()
	for _, val := range *obj.fieldPtr {
		obj.appendHolderSlice(&link{obj: val})
	}
	obj.obj = msg
	return obj
}

func (obj *configLinkIter) Items() []Link {
	return obj.linkSlice
}

func (obj *configLinkIter) Add() Link {
	newObj := &l1s_pb.Link{}
	*obj.fieldPtr = append(*obj.fieldPtr, newObj)
	newLibObj := &link{obj: newObj}
	newLibObj.setDefault()
	obj.linkSlice = append(obj.linkSlice, newLibObj)
	return newLibObj
}

func (obj *configLinkIter) Append(items ...Link) ConfigLinkIter {
	for _, item := range items {
		newObj := item.msg()
		*obj.fieldPtr = append(*obj.fieldPtr, newObj)
		obj.linkSlice = append(obj.linkSlice, item)
	}
	return obj
}

func (obj *configLinkIter) Set(index int, newObj Link) ConfigLinkIter {
	(*obj.fieldPtr)[index] = newObj.msg()
	obj.linkSlice[index] = newObj
	return obj
}
func (obj *configLinkIter) Clear() ConfigLinkIter {
	if len(*obj.fieldPtr) > 0 {
		*obj.fieldPtr = []*l1s_pb.Link{}
		obj.linkSlice = []Link{}
	}
	return obj
}
func (obj *configLinkIter) clearHolderSlice() ConfigLinkIter {
	if len(obj.linkSlice) > 0 {
		obj.linkSlice = []Link{}
	}
	return obj
}
func (obj *configLinkIter) appendHolderSlice(item Link) ConfigLinkIter {
	obj.linkSlice = append(obj.linkSlice, item)
	return obj
}

func (obj *config) validateObj(vObj *validation, set_default bool) {
	if set_default {
		obj.setDefault()
	}

	if len(obj.obj.Links) != 0 {

		if set_default {
			obj.Links().clearHolderSlice()
			for _, item := range obj.obj.Links {
				obj.Links().appendHolderSlice(&link{obj: item})
			}
		}
		for _, item := range obj.Links().Items() {
			item.validateObj(vObj, set_default)
		}

	}

}

func (obj *config) setDefault() {

}

// ***** SetConfigResponse *****
type setConfigResponse struct {
	validation
	obj          *l1s_pb.SetConfigResponse
	marshaller   marshalSetConfigResponse
	unMarshaller unMarshalSetConfigResponse
}

func NewSetConfigResponse() SetConfigResponse {
	obj := setConfigResponse{obj: &l1s_pb.SetConfigResponse{}}
	obj.setDefault()
	return &obj
}

func (obj *setConfigResponse) msg() *l1s_pb.SetConfigResponse {
	return obj.obj
}

func (obj *setConfigResponse) setMsg(msg *l1s_pb.SetConfigResponse) SetConfigResponse {

	proto.Merge(obj.obj, msg)
	return obj
}

type marshalsetConfigResponse struct {
	obj *setConfigResponse
}

type marshalSetConfigResponse interface {
	// ToProto marshals SetConfigResponse to protobuf object *l1s_pb.SetConfigResponse
	ToProto() (*l1s_pb.SetConfigResponse, error)
	// ToPbText marshals SetConfigResponse to protobuf text
	ToPbText() (string, error)
	// ToYaml marshals SetConfigResponse to YAML text
	ToYaml() (string, error)
	// ToJson marshals SetConfigResponse to JSON text
	ToJson() (string, error)
}

type unMarshalsetConfigResponse struct {
	obj *setConfigResponse
}

type unMarshalSetConfigResponse interface {
	// FromProto unmarshals SetConfigResponse from protobuf object *l1s_pb.SetConfigResponse
	FromProto(msg *l1s_pb.SetConfigResponse) (SetConfigResponse, error)
	// FromPbText unmarshals SetConfigResponse from protobuf text
	FromPbText(value string) error
	// FromYaml unmarshals SetConfigResponse from YAML text
	FromYaml(value string) error
	// FromJson unmarshals SetConfigResponse from JSON text
	FromJson(value string) error
}

func (obj *setConfigResponse) Marshal() marshalSetConfigResponse {
	if obj.marshaller == nil {
		obj.marshaller = &marshalsetConfigResponse{obj: obj}
	}
	return obj.marshaller
}

func (obj *setConfigResponse) Unmarshal() unMarshalSetConfigResponse {
	if obj.unMarshaller == nil {
		obj.unMarshaller = &unMarshalsetConfigResponse{obj: obj}
	}
	return obj.unMarshaller
}

func (m *marshalsetConfigResponse) ToProto() (*l1s_pb.SetConfigResponse, error) {
	err := m.obj.validateToAndFrom()
	if err != nil {
		return nil, err
	}
	return m.obj.msg(), nil
}

func (m *unMarshalsetConfigResponse) FromProto(msg *l1s_pb.SetConfigResponse) (SetConfigResponse, error) {
	newObj := m.obj.setMsg(msg)
	err := newObj.validateToAndFrom()
	if err != nil {
		return nil, err
	}
	return newObj, nil
}

func (m *marshalsetConfigResponse) ToPbText() (string, error) {
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return "", vErr
	}
	protoMarshal, err := proto.Marshal(m.obj.msg())
	if err != nil {
		return "", err
	}
	return string(protoMarshal), nil
}

func (m *unMarshalsetConfigResponse) FromPbText(value string) error {
	retObj := proto.Unmarshal([]byte(value), m.obj.msg())
	if retObj != nil {
		return retObj
	}

	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return vErr
	}
	return retObj
}

func (m *marshalsetConfigResponse) ToYaml() (string, error) {
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return "", vErr
	}
	opts := protojson.MarshalOptions{
		UseProtoNames:   true,
		AllowPartial:    true,
		EmitUnpopulated: false,
	}
	data, err := opts.Marshal(m.obj.msg())
	if err != nil {
		return "", err
	}
	data, err = yaml.JSONToYAML(data)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (m *unMarshalsetConfigResponse) FromYaml(value string) error {
	if value == "" {
		value = "{}"
	}
	data, err := yaml.YAMLToJSON([]byte(value))
	if err != nil {
		return err
	}
	opts := protojson.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: false,
	}
	uError := opts.Unmarshal([]byte(data), m.obj.msg())
	if uError != nil {
		return fmt.Errorf("unmarshal error %s", strings.Replace(
			uError.Error(), "\u00a0", " ", -1)[7:])
	}

	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return vErr
	}
	return nil
}

func (m *marshalsetConfigResponse) ToJson() (string, error) {
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return "", vErr
	}
	opts := protojson.MarshalOptions{
		UseProtoNames:   true,
		AllowPartial:    true,
		EmitUnpopulated: false,
		Indent:          "  ",
	}
	data, err := opts.Marshal(m.obj.msg())
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (m *unMarshalsetConfigResponse) FromJson(value string) error {
	opts := protojson.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: false,
	}
	if value == "" {
		value = "{}"
	}
	uError := opts.Unmarshal([]byte(value), m.obj.msg())
	if uError != nil {
		return fmt.Errorf("unmarshal error %s", strings.Replace(
			uError.Error(), "\u00a0", " ", -1)[7:])
	}

	err := m.obj.validateToAndFrom()
	if err != nil {
		return err
	}
	return nil
}

func (obj *setConfigResponse) validateToAndFrom() error {
	// emptyVars()
	obj.validateObj(&obj.validation, true)
	return obj.validationResult()
}

func (obj *setConfigResponse) validate() error {
	// emptyVars()
	obj.validateObj(&obj.validation, false)
	return obj.validationResult()
}

func (obj *setConfigResponse) String() string {
	str, err := obj.Marshal().ToYaml()
	if err != nil {
		return err.Error()
	}
	return str
}

func (obj *setConfigResponse) Clone() (SetConfigResponse, error) {
	vErr := obj.validate()
	if vErr != nil {
		return nil, vErr
	}
	newObj := NewSetConfigResponse()
	data, err := proto.Marshal(obj.msg())
	if err != nil {
		return nil, err
	}
	pbErr := proto.Unmarshal(data, newObj.msg())
	if pbErr != nil {
		return nil, pbErr
	}
	return newObj, nil
}

// SetConfigResponse is description is TBD
type SetConfigResponse interface {
	Validation
	// msg marshals SetConfigResponse to protobuf object *l1s_pb.SetConfigResponse
	// and doesn't set defaults
	msg() *l1s_pb.SetConfigResponse
	// setMsg unmarshals SetConfigResponse from protobuf object *l1s_pb.SetConfigResponse
	// and doesn't set defaults
	setMsg(*l1s_pb.SetConfigResponse) SetConfigResponse
	// provides marshal interface
	Marshal() marshalSetConfigResponse
	// provides unmarshal interface
	Unmarshal() unMarshalSetConfigResponse
	// validate validates SetConfigResponse
	validate() error
	// A stringer function
	String() string
	// Clones the object
	Clone() (SetConfigResponse, error)
	validateToAndFrom() error
	validateObj(vObj *validation, set_default bool)
	setDefault()
	// ResponseString returns string, set in SetConfigResponse.
	ResponseString() string
	// SetResponseString assigns string provided by user to SetConfigResponse
	SetResponseString(value string) SetConfigResponse
	// HasResponseString checks if ResponseString has been set in SetConfigResponse
	HasResponseString() bool
}

// description is TBD
// ResponseString returns a string
func (obj *setConfigResponse) ResponseString() string {
	return obj.obj.String_
}

// description is TBD
// ResponseString returns a string
func (obj *setConfigResponse) HasResponseString() bool {
	return obj.obj.String_ != ""
}

// description is TBD
// SetResponseString sets the string value in the SetConfigResponse object
func (obj *setConfigResponse) SetResponseString(value string) SetConfigResponse {
	obj.obj.String_ = value
	return obj
}

func (obj *setConfigResponse) validateObj(vObj *validation, set_default bool) {
	if set_default {
		obj.setDefault()
	}

}

func (obj *setConfigResponse) setDefault() {

}

// ***** GetVersionResponse *****
type getVersionResponse struct {
	validation
	obj           *l1s_pb.GetVersionResponse
	marshaller    marshalGetVersionResponse
	unMarshaller  unMarshalGetVersionResponse
	versionHolder Version
}

func NewGetVersionResponse() GetVersionResponse {
	obj := getVersionResponse{obj: &l1s_pb.GetVersionResponse{}}
	obj.setDefault()
	return &obj
}

func (obj *getVersionResponse) msg() *l1s_pb.GetVersionResponse {
	return obj.obj
}

func (obj *getVersionResponse) setMsg(msg *l1s_pb.GetVersionResponse) GetVersionResponse {
	obj.setNil()
	proto.Merge(obj.obj, msg)
	return obj
}

type marshalgetVersionResponse struct {
	obj *getVersionResponse
}

type marshalGetVersionResponse interface {
	// ToProto marshals GetVersionResponse to protobuf object *l1s_pb.GetVersionResponse
	ToProto() (*l1s_pb.GetVersionResponse, error)
	// ToPbText marshals GetVersionResponse to protobuf text
	ToPbText() (string, error)
	// ToYaml marshals GetVersionResponse to YAML text
	ToYaml() (string, error)
	// ToJson marshals GetVersionResponse to JSON text
	ToJson() (string, error)
}

type unMarshalgetVersionResponse struct {
	obj *getVersionResponse
}

type unMarshalGetVersionResponse interface {
	// FromProto unmarshals GetVersionResponse from protobuf object *l1s_pb.GetVersionResponse
	FromProto(msg *l1s_pb.GetVersionResponse) (GetVersionResponse, error)
	// FromPbText unmarshals GetVersionResponse from protobuf text
	FromPbText(value string) error
	// FromYaml unmarshals GetVersionResponse from YAML text
	FromYaml(value string) error
	// FromJson unmarshals GetVersionResponse from JSON text
	FromJson(value string) error
}

func (obj *getVersionResponse) Marshal() marshalGetVersionResponse {
	if obj.marshaller == nil {
		obj.marshaller = &marshalgetVersionResponse{obj: obj}
	}
	return obj.marshaller
}

func (obj *getVersionResponse) Unmarshal() unMarshalGetVersionResponse {
	if obj.unMarshaller == nil {
		obj.unMarshaller = &unMarshalgetVersionResponse{obj: obj}
	}
	return obj.unMarshaller
}

func (m *marshalgetVersionResponse) ToProto() (*l1s_pb.GetVersionResponse, error) {
	err := m.obj.validateToAndFrom()
	if err != nil {
		return nil, err
	}
	return m.obj.msg(), nil
}

func (m *unMarshalgetVersionResponse) FromProto(msg *l1s_pb.GetVersionResponse) (GetVersionResponse, error) {
	newObj := m.obj.setMsg(msg)
	err := newObj.validateToAndFrom()
	if err != nil {
		return nil, err
	}
	return newObj, nil
}

func (m *marshalgetVersionResponse) ToPbText() (string, error) {
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return "", vErr
	}
	protoMarshal, err := proto.Marshal(m.obj.msg())
	if err != nil {
		return "", err
	}
	return string(protoMarshal), nil
}

func (m *unMarshalgetVersionResponse) FromPbText(value string) error {
	retObj := proto.Unmarshal([]byte(value), m.obj.msg())
	if retObj != nil {
		return retObj
	}
	m.obj.setNil()
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return vErr
	}
	return retObj
}

func (m *marshalgetVersionResponse) ToYaml() (string, error) {
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return "", vErr
	}
	opts := protojson.MarshalOptions{
		UseProtoNames:   true,
		AllowPartial:    true,
		EmitUnpopulated: false,
	}
	data, err := opts.Marshal(m.obj.msg())
	if err != nil {
		return "", err
	}
	data, err = yaml.JSONToYAML(data)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (m *unMarshalgetVersionResponse) FromYaml(value string) error {
	if value == "" {
		value = "{}"
	}
	data, err := yaml.YAMLToJSON([]byte(value))
	if err != nil {
		return err
	}
	opts := protojson.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: false,
	}
	uError := opts.Unmarshal([]byte(data), m.obj.msg())
	if uError != nil {
		return fmt.Errorf("unmarshal error %s", strings.Replace(
			uError.Error(), "\u00a0", " ", -1)[7:])
	}
	m.obj.setNil()
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return vErr
	}
	return nil
}

func (m *marshalgetVersionResponse) ToJson() (string, error) {
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return "", vErr
	}
	opts := protojson.MarshalOptions{
		UseProtoNames:   true,
		AllowPartial:    true,
		EmitUnpopulated: false,
		Indent:          "  ",
	}
	data, err := opts.Marshal(m.obj.msg())
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (m *unMarshalgetVersionResponse) FromJson(value string) error {
	opts := protojson.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: false,
	}
	if value == "" {
		value = "{}"
	}
	uError := opts.Unmarshal([]byte(value), m.obj.msg())
	if uError != nil {
		return fmt.Errorf("unmarshal error %s", strings.Replace(
			uError.Error(), "\u00a0", " ", -1)[7:])
	}
	m.obj.setNil()
	err := m.obj.validateToAndFrom()
	if err != nil {
		return err
	}
	return nil
}

func (obj *getVersionResponse) validateToAndFrom() error {
	// emptyVars()
	obj.validateObj(&obj.validation, true)
	return obj.validationResult()
}

func (obj *getVersionResponse) validate() error {
	// emptyVars()
	obj.validateObj(&obj.validation, false)
	return obj.validationResult()
}

func (obj *getVersionResponse) String() string {
	str, err := obj.Marshal().ToYaml()
	if err != nil {
		return err.Error()
	}
	return str
}

func (obj *getVersionResponse) Clone() (GetVersionResponse, error) {
	vErr := obj.validate()
	if vErr != nil {
		return nil, vErr
	}
	newObj := NewGetVersionResponse()
	data, err := proto.Marshal(obj.msg())
	if err != nil {
		return nil, err
	}
	pbErr := proto.Unmarshal(data, newObj.msg())
	if pbErr != nil {
		return nil, pbErr
	}
	return newObj, nil
}

func (obj *getVersionResponse) setNil() {
	obj.versionHolder = nil
	obj.validationErrors = nil
	obj.warnings = nil
	obj.constraints = make(map[string]map[string]Constraints)
}

// GetVersionResponse is description is TBD
type GetVersionResponse interface {
	Validation
	// msg marshals GetVersionResponse to protobuf object *l1s_pb.GetVersionResponse
	// and doesn't set defaults
	msg() *l1s_pb.GetVersionResponse
	// setMsg unmarshals GetVersionResponse from protobuf object *l1s_pb.GetVersionResponse
	// and doesn't set defaults
	setMsg(*l1s_pb.GetVersionResponse) GetVersionResponse
	// provides marshal interface
	Marshal() marshalGetVersionResponse
	// provides unmarshal interface
	Unmarshal() unMarshalGetVersionResponse
	// validate validates GetVersionResponse
	validate() error
	// A stringer function
	String() string
	// Clones the object
	Clone() (GetVersionResponse, error)
	validateToAndFrom() error
	validateObj(vObj *validation, set_default bool)
	setDefault()
	// Version returns Version, set in GetVersionResponse.
	// Version is version details
	Version() Version
	// SetVersion assigns Version provided by user to GetVersionResponse.
	// Version is version details
	SetVersion(value Version) GetVersionResponse
	// HasVersion checks if Version has been set in GetVersionResponse
	HasVersion() bool
	setNil()
}

// description is TBD
// Version returns a Version
func (obj *getVersionResponse) Version() Version {
	if obj.obj.Version == nil {
		obj.obj.Version = NewVersion().msg()
	}
	if obj.versionHolder == nil {
		obj.versionHolder = &version{obj: obj.obj.Version}
	}
	return obj.versionHolder
}

// description is TBD
// Version returns a Version
func (obj *getVersionResponse) HasVersion() bool {
	return obj.obj.Version != nil
}

// description is TBD
// SetVersion sets the Version value in the GetVersionResponse object
func (obj *getVersionResponse) SetVersion(value Version) GetVersionResponse {

	obj.versionHolder = nil
	obj.obj.Version = value.msg()

	return obj
}

func (obj *getVersionResponse) validateObj(vObj *validation, set_default bool) {
	if set_default {
		obj.setDefault()
	}

	if obj.obj.Version != nil {

		obj.Version().validateObj(vObj, set_default)
	}

}

func (obj *getVersionResponse) setDefault() {

}

// ***** Link *****
type link struct {
	validation
	obj          *l1s_pb.Link
	marshaller   marshalLink
	unMarshaller unMarshalLink
}

func NewLink() Link {
	obj := link{obj: &l1s_pb.Link{}}
	obj.setDefault()
	return &obj
}

func (obj *link) msg() *l1s_pb.Link {
	return obj.obj
}

func (obj *link) setMsg(msg *l1s_pb.Link) Link {

	proto.Merge(obj.obj, msg)
	return obj
}

type marshallink struct {
	obj *link
}

type marshalLink interface {
	// ToProto marshals Link to protobuf object *l1s_pb.Link
	ToProto() (*l1s_pb.Link, error)
	// ToPbText marshals Link to protobuf text
	ToPbText() (string, error)
	// ToYaml marshals Link to YAML text
	ToYaml() (string, error)
	// ToJson marshals Link to JSON text
	ToJson() (string, error)
}

type unMarshallink struct {
	obj *link
}

type unMarshalLink interface {
	// FromProto unmarshals Link from protobuf object *l1s_pb.Link
	FromProto(msg *l1s_pb.Link) (Link, error)
	// FromPbText unmarshals Link from protobuf text
	FromPbText(value string) error
	// FromYaml unmarshals Link from YAML text
	FromYaml(value string) error
	// FromJson unmarshals Link from JSON text
	FromJson(value string) error
}

func (obj *link) Marshal() marshalLink {
	if obj.marshaller == nil {
		obj.marshaller = &marshallink{obj: obj}
	}
	return obj.marshaller
}

func (obj *link) Unmarshal() unMarshalLink {
	if obj.unMarshaller == nil {
		obj.unMarshaller = &unMarshallink{obj: obj}
	}
	return obj.unMarshaller
}

func (m *marshallink) ToProto() (*l1s_pb.Link, error) {
	err := m.obj.validateToAndFrom()
	if err != nil {
		return nil, err
	}
	return m.obj.msg(), nil
}

func (m *unMarshallink) FromProto(msg *l1s_pb.Link) (Link, error) {
	newObj := m.obj.setMsg(msg)
	err := newObj.validateToAndFrom()
	if err != nil {
		return nil, err
	}
	return newObj, nil
}

func (m *marshallink) ToPbText() (string, error) {
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return "", vErr
	}
	protoMarshal, err := proto.Marshal(m.obj.msg())
	if err != nil {
		return "", err
	}
	return string(protoMarshal), nil
}

func (m *unMarshallink) FromPbText(value string) error {
	retObj := proto.Unmarshal([]byte(value), m.obj.msg())
	if retObj != nil {
		return retObj
	}

	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return vErr
	}
	return retObj
}

func (m *marshallink) ToYaml() (string, error) {
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return "", vErr
	}
	opts := protojson.MarshalOptions{
		UseProtoNames:   true,
		AllowPartial:    true,
		EmitUnpopulated: false,
	}
	data, err := opts.Marshal(m.obj.msg())
	if err != nil {
		return "", err
	}
	data, err = yaml.JSONToYAML(data)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (m *unMarshallink) FromYaml(value string) error {
	if value == "" {
		value = "{}"
	}
	data, err := yaml.YAMLToJSON([]byte(value))
	if err != nil {
		return err
	}
	opts := protojson.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: false,
	}
	uError := opts.Unmarshal([]byte(data), m.obj.msg())
	if uError != nil {
		return fmt.Errorf("unmarshal error %s", strings.Replace(
			uError.Error(), "\u00a0", " ", -1)[7:])
	}

	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return vErr
	}
	return nil
}

func (m *marshallink) ToJson() (string, error) {
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return "", vErr
	}
	opts := protojson.MarshalOptions{
		UseProtoNames:   true,
		AllowPartial:    true,
		EmitUnpopulated: false,
		Indent:          "  ",
	}
	data, err := opts.Marshal(m.obj.msg())
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (m *unMarshallink) FromJson(value string) error {
	opts := protojson.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: false,
	}
	if value == "" {
		value = "{}"
	}
	uError := opts.Unmarshal([]byte(value), m.obj.msg())
	if uError != nil {
		return fmt.Errorf("unmarshal error %s", strings.Replace(
			uError.Error(), "\u00a0", " ", -1)[7:])
	}

	err := m.obj.validateToAndFrom()
	if err != nil {
		return err
	}
	return nil
}

func (obj *link) validateToAndFrom() error {
	// emptyVars()
	obj.validateObj(&obj.validation, true)
	return obj.validationResult()
}

func (obj *link) validate() error {
	// emptyVars()
	obj.validateObj(&obj.validation, false)
	return obj.validationResult()
}

func (obj *link) String() string {
	str, err := obj.Marshal().ToYaml()
	if err != nil {
		return err.Error()
	}
	return str
}

func (obj *link) Clone() (Link, error) {
	vErr := obj.validate()
	if vErr != nil {
		return nil, vErr
	}
	newObj := NewLink()
	data, err := proto.Marshal(obj.msg())
	if err != nil {
		return nil, err
	}
	pbErr := proto.Unmarshal(data, newObj.msg())
	if pbErr != nil {
		return nil, pbErr
	}
	return newObj, nil
}

// Link is link between the Ports.
type Link interface {
	Validation
	// msg marshals Link to protobuf object *l1s_pb.Link
	// and doesn't set defaults
	msg() *l1s_pb.Link
	// setMsg unmarshals Link from protobuf object *l1s_pb.Link
	// and doesn't set defaults
	setMsg(*l1s_pb.Link) Link
	// provides marshal interface
	Marshal() marshalLink
	// provides unmarshal interface
	Unmarshal() unMarshalLink
	// validate validates Link
	validate() error
	// A stringer function
	String() string
	// Clones the object
	Clone() (Link, error)
	validateToAndFrom() error
	validateObj(vObj *validation, set_default bool)
	setDefault()
	// Src returns string, set in Link.
	Src() string
	// SetSrc assigns string provided by user to Link
	SetSrc(value string) Link
	// Dst returns string, set in Link.
	Dst() string
	// SetDst assigns string provided by user to Link
	SetDst(value string) Link
	// Mode returns LinkModeEnum, set in Link
	Mode() LinkModeEnum
	// SetMode assigns LinkModeEnum provided by user to Link
	SetMode(value LinkModeEnum) Link
	// HasMode checks if Mode has been set in Link
	HasMode() bool
}

// Src for the link.
// Src returns a string
func (obj *link) Src() string {

	return *obj.obj.Src

}

// Src for the link.
// SetSrc sets the string value in the Link object
func (obj *link) SetSrc(value string) Link {

	obj.obj.Src = &value
	return obj
}

// Dst of the link.
// Dst returns a string
func (obj *link) Dst() string {

	return *obj.obj.Dst

}

// Dst of the link.
// SetDst sets the string value in the Link object
func (obj *link) SetDst(value string) Link {

	obj.obj.Dst = &value
	return obj
}

type LinkModeEnum string

// Enum of Mode on Link
var LinkMode = struct {
	UNIDIRECTIONAL LinkModeEnum
	BIDIRECTIONAL  LinkModeEnum
}{
	UNIDIRECTIONAL: LinkModeEnum("unidirectional"),
	BIDIRECTIONAL:  LinkModeEnum("bidirectional"),
}

func (obj *link) Mode() LinkModeEnum {
	return LinkModeEnum(obj.obj.Mode.Enum().String())
}

// description is TBD
// Mode returns a string
func (obj *link) HasMode() bool {
	return obj.obj.Mode != nil
}

func (obj *link) SetMode(value LinkModeEnum) Link {
	intValue, ok := l1s_pb.Link_Mode_Enum_value[string(value)]
	if !ok {
		obj.validationErrors = append(obj.validationErrors, fmt.Sprintf(
			"%s is not a valid choice on LinkModeEnum", string(value)))
		return obj
	}
	enumValue := l1s_pb.Link_Mode_Enum(intValue)
	obj.obj.Mode = &enumValue

	return obj
}

func (obj *link) validateObj(vObj *validation, set_default bool) {
	if set_default {
		obj.setDefault()
	}

	// Src is required
	if obj.obj.Src == nil {
		vObj.validationErrors = append(vObj.validationErrors, "Src is required field on interface Link")
	}

	// Dst is required
	if obj.obj.Dst == nil {
		vObj.validationErrors = append(vObj.validationErrors, "Dst is required field on interface Link")
	}
}

func (obj *link) setDefault() {
	if obj.obj.Mode == nil {
		obj.SetMode(LinkMode.BIDIRECTIONAL)

	}

}

// ***** Error *****
type _error struct {
	validation
	obj          *l1s_pb.Error
	marshaller   marshalError
	unMarshaller unMarshalError
}

func NewError() Error {
	obj := _error{obj: &l1s_pb.Error{}}
	obj.setDefault()
	return &obj
}

func (obj *_error) msg() *l1s_pb.Error {
	return obj.obj
}

func (obj *_error) setMsg(msg *l1s_pb.Error) Error {

	proto.Merge(obj.obj, msg)
	return obj
}

type marshal_error struct {
	obj *_error
}

type marshalError interface {
	// ToProto marshals Error to protobuf object *l1s_pb.Error
	ToProto() (*l1s_pb.Error, error)
	// ToPbText marshals Error to protobuf text
	ToPbText() (string, error)
	// ToYaml marshals Error to YAML text
	ToYaml() (string, error)
	// ToJson marshals Error to JSON text
	ToJson() (string, error)
}

type unMarshal_error struct {
	obj *_error
}

type unMarshalError interface {
	// FromProto unmarshals Error from protobuf object *l1s_pb.Error
	FromProto(msg *l1s_pb.Error) (Error, error)
	// FromPbText unmarshals Error from protobuf text
	FromPbText(value string) error
	// FromYaml unmarshals Error from YAML text
	FromYaml(value string) error
	// FromJson unmarshals Error from JSON text
	FromJson(value string) error
}

func (obj *_error) Marshal() marshalError {
	if obj.marshaller == nil {
		obj.marshaller = &marshal_error{obj: obj}
	}
	return obj.marshaller
}

func (obj *_error) Unmarshal() unMarshalError {
	if obj.unMarshaller == nil {
		obj.unMarshaller = &unMarshal_error{obj: obj}
	}
	return obj.unMarshaller
}

func (m *marshal_error) ToProto() (*l1s_pb.Error, error) {
	err := m.obj.validateToAndFrom()
	if err != nil {
		return nil, err
	}
	return m.obj.msg(), nil
}

func (m *unMarshal_error) FromProto(msg *l1s_pb.Error) (Error, error) {
	newObj := m.obj.setMsg(msg)
	err := newObj.validateToAndFrom()
	if err != nil {
		return nil, err
	}
	return newObj, nil
}

func (m *marshal_error) ToPbText() (string, error) {
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return "", vErr
	}
	protoMarshal, err := proto.Marshal(m.obj.msg())
	if err != nil {
		return "", err
	}
	return string(protoMarshal), nil
}

func (m *unMarshal_error) FromPbText(value string) error {
	retObj := proto.Unmarshal([]byte(value), m.obj.msg())
	if retObj != nil {
		return retObj
	}

	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return vErr
	}
	return retObj
}

func (m *marshal_error) ToYaml() (string, error) {
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return "", vErr
	}
	opts := protojson.MarshalOptions{
		UseProtoNames:   true,
		AllowPartial:    true,
		EmitUnpopulated: false,
	}
	data, err := opts.Marshal(m.obj.msg())
	if err != nil {
		return "", err
	}
	data, err = yaml.JSONToYAML(data)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (m *unMarshal_error) FromYaml(value string) error {
	if value == "" {
		value = "{}"
	}
	data, err := yaml.YAMLToJSON([]byte(value))
	if err != nil {
		return err
	}
	opts := protojson.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: false,
	}
	uError := opts.Unmarshal([]byte(data), m.obj.msg())
	if uError != nil {
		return fmt.Errorf("unmarshal error %s", strings.Replace(
			uError.Error(), "\u00a0", " ", -1)[7:])
	}

	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return vErr
	}
	return nil
}

func (m *marshal_error) ToJson() (string, error) {
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return "", vErr
	}
	opts := protojson.MarshalOptions{
		UseProtoNames:   true,
		AllowPartial:    true,
		EmitUnpopulated: false,
		Indent:          "  ",
	}
	data, err := opts.Marshal(m.obj.msg())
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (m *unMarshal_error) FromJson(value string) error {
	opts := protojson.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: false,
	}
	if value == "" {
		value = "{}"
	}
	uError := opts.Unmarshal([]byte(value), m.obj.msg())
	if uError != nil {
		return fmt.Errorf("unmarshal error %s", strings.Replace(
			uError.Error(), "\u00a0", " ", -1)[7:])
	}

	err := m.obj.validateToAndFrom()
	if err != nil {
		return err
	}
	return nil
}

func (obj *_error) validateToAndFrom() error {
	// emptyVars()
	obj.validateObj(&obj.validation, true)
	return obj.validationResult()
}

func (obj *_error) validate() error {
	// emptyVars()
	obj.validateObj(&obj.validation, false)
	return obj.validationResult()
}

func (obj *_error) String() string {
	str, err := obj.Marshal().ToYaml()
	if err != nil {
		return err.Error()
	}
	return str
}

func (obj *_error) Clone() (Error, error) {
	vErr := obj.validate()
	if vErr != nil {
		return nil, vErr
	}
	newObj := NewError()
	data, err := proto.Marshal(obj.msg())
	if err != nil {
		return nil, err
	}
	pbErr := proto.Unmarshal(data, newObj.msg())
	if pbErr != nil {
		return nil, pbErr
	}
	return newObj, nil
}

// Error is error response generated while serving API request.
type Error interface {
	Validation
	// msg marshals Error to protobuf object *l1s_pb.Error
	// and doesn't set defaults
	msg() *l1s_pb.Error
	// setMsg unmarshals Error from protobuf object *l1s_pb.Error
	// and doesn't set defaults
	setMsg(*l1s_pb.Error) Error
	// provides marshal interface
	Marshal() marshalError
	// provides unmarshal interface
	Unmarshal() unMarshalError
	// validate validates Error
	validate() error
	// A stringer function
	String() string
	// Clones the object
	Clone() (Error, error)
	validateToAndFrom() error
	validateObj(vObj *validation, set_default bool)
	setDefault()
	// Code returns int32, set in Error.
	Code() int32
	// SetCode assigns int32 provided by user to Error
	SetCode(value int32) Error
	// Kind returns ErrorKindEnum, set in Error
	Kind() ErrorKindEnum
	// SetKind assigns ErrorKindEnum provided by user to Error
	SetKind(value ErrorKindEnum) Error
	// HasKind checks if Kind has been set in Error
	HasKind() bool
	// Errors returns []string, set in Error.
	Errors() []string
	// SetErrors assigns []string provided by user to Error
	SetErrors(value []string) Error
	// implement Error function for implementingnative Error Interface.
	Error() string
}

func (obj *_error) Error() string {
	json, err := obj.Marshal().ToJson()
	if err != nil {
		return fmt.Sprintf("could not convert Error to JSON: %v", err)
	}
	return json
}

// Numeric status code based on the underlying transport being used.
// The API server MUST set this code explicitly based on following references:
// - HTTP 4xx errors: https://datatracker.ietf.org/doc/html/rfc9110#section-15.5
// - HTTP 5xx errors: https://datatracker.ietf.org/doc/html/rfc9110#section-15.6
// - gRPC errors: https://grpc.github.io/grpc/core/md_doc_statuscodes.html
// Code returns a int32
func (obj *_error) Code() int32 {

	return *obj.obj.Code

}

// Numeric status code based on the underlying transport being used.
// The API server MUST set this code explicitly based on following references:
// - HTTP 4xx errors: https://datatracker.ietf.org/doc/html/rfc9110#section-15.5
// - HTTP 5xx errors: https://datatracker.ietf.org/doc/html/rfc9110#section-15.6
// - gRPC errors: https://grpc.github.io/grpc/core/md_doc_statuscodes.html
// SetCode sets the int32 value in the Error object
func (obj *_error) SetCode(value int32) Error {

	obj.obj.Code = &value
	return obj
}

type ErrorKindEnum string

// Enum of Kind on Error
var ErrorKind = struct {
	VALIDATION ErrorKindEnum
	INTERNAL   ErrorKindEnum
}{
	VALIDATION: ErrorKindEnum("validation"),
	INTERNAL:   ErrorKindEnum("internal"),
}

func (obj *_error) Kind() ErrorKindEnum {
	return ErrorKindEnum(obj.obj.Kind.Enum().String())
}

// Classification of error originating from within API server that may not be mapped to the value in `code`.
// Absence of this field may indicate that the error did not originate from within API server.
// Kind returns a string
func (obj *_error) HasKind() bool {
	return obj.obj.Kind != nil
}

func (obj *_error) SetKind(value ErrorKindEnum) Error {
	intValue, ok := l1s_pb.Error_Kind_Enum_value[string(value)]
	if !ok {
		obj.validationErrors = append(obj.validationErrors, fmt.Sprintf(
			"%s is not a valid choice on ErrorKindEnum", string(value)))
		return obj
	}
	enumValue := l1s_pb.Error_Kind_Enum(intValue)
	obj.obj.Kind = &enumValue

	return obj
}

// List of error messages generated while executing the request.
// Errors returns a []string
func (obj *_error) Errors() []string {
	if obj.obj.Errors == nil {
		obj.obj.Errors = make([]string, 0)
	}
	return obj.obj.Errors
}

// List of error messages generated while executing the request.
// SetErrors sets the []string value in the Error object
func (obj *_error) SetErrors(value []string) Error {

	if obj.obj.Errors == nil {
		obj.obj.Errors = make([]string, 0)
	}
	obj.obj.Errors = value

	return obj
}

func (obj *_error) validateObj(vObj *validation, set_default bool) {
	if set_default {
		obj.setDefault()
	}

	// Code is required
	if obj.obj.Code == nil {
		vObj.validationErrors = append(vObj.validationErrors, "Code is required field on interface Error")
	}
}

func (obj *_error) setDefault() {

}

// ***** Version *****
type version struct {
	validation
	obj          *l1s_pb.Version
	marshaller   marshalVersion
	unMarshaller unMarshalVersion
}

func NewVersion() Version {
	obj := version{obj: &l1s_pb.Version{}}
	obj.setDefault()
	return &obj
}

func (obj *version) msg() *l1s_pb.Version {
	return obj.obj
}

func (obj *version) setMsg(msg *l1s_pb.Version) Version {

	proto.Merge(obj.obj, msg)
	return obj
}

type marshalversion struct {
	obj *version
}

type marshalVersion interface {
	// ToProto marshals Version to protobuf object *l1s_pb.Version
	ToProto() (*l1s_pb.Version, error)
	// ToPbText marshals Version to protobuf text
	ToPbText() (string, error)
	// ToYaml marshals Version to YAML text
	ToYaml() (string, error)
	// ToJson marshals Version to JSON text
	ToJson() (string, error)
}

type unMarshalversion struct {
	obj *version
}

type unMarshalVersion interface {
	// FromProto unmarshals Version from protobuf object *l1s_pb.Version
	FromProto(msg *l1s_pb.Version) (Version, error)
	// FromPbText unmarshals Version from protobuf text
	FromPbText(value string) error
	// FromYaml unmarshals Version from YAML text
	FromYaml(value string) error
	// FromJson unmarshals Version from JSON text
	FromJson(value string) error
}

func (obj *version) Marshal() marshalVersion {
	if obj.marshaller == nil {
		obj.marshaller = &marshalversion{obj: obj}
	}
	return obj.marshaller
}

func (obj *version) Unmarshal() unMarshalVersion {
	if obj.unMarshaller == nil {
		obj.unMarshaller = &unMarshalversion{obj: obj}
	}
	return obj.unMarshaller
}

func (m *marshalversion) ToProto() (*l1s_pb.Version, error) {
	err := m.obj.validateToAndFrom()
	if err != nil {
		return nil, err
	}
	return m.obj.msg(), nil
}

func (m *unMarshalversion) FromProto(msg *l1s_pb.Version) (Version, error) {
	newObj := m.obj.setMsg(msg)
	err := newObj.validateToAndFrom()
	if err != nil {
		return nil, err
	}
	return newObj, nil
}

func (m *marshalversion) ToPbText() (string, error) {
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return "", vErr
	}
	protoMarshal, err := proto.Marshal(m.obj.msg())
	if err != nil {
		return "", err
	}
	return string(protoMarshal), nil
}

func (m *unMarshalversion) FromPbText(value string) error {
	retObj := proto.Unmarshal([]byte(value), m.obj.msg())
	if retObj != nil {
		return retObj
	}

	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return vErr
	}
	return retObj
}

func (m *marshalversion) ToYaml() (string, error) {
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return "", vErr
	}
	opts := protojson.MarshalOptions{
		UseProtoNames:   true,
		AllowPartial:    true,
		EmitUnpopulated: false,
	}
	data, err := opts.Marshal(m.obj.msg())
	if err != nil {
		return "", err
	}
	data, err = yaml.JSONToYAML(data)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (m *unMarshalversion) FromYaml(value string) error {
	if value == "" {
		value = "{}"
	}
	data, err := yaml.YAMLToJSON([]byte(value))
	if err != nil {
		return err
	}
	opts := protojson.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: false,
	}
	uError := opts.Unmarshal([]byte(data), m.obj.msg())
	if uError != nil {
		return fmt.Errorf("unmarshal error %s", strings.Replace(
			uError.Error(), "\u00a0", " ", -1)[7:])
	}

	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return vErr
	}
	return nil
}

func (m *marshalversion) ToJson() (string, error) {
	vErr := m.obj.validateToAndFrom()
	if vErr != nil {
		return "", vErr
	}
	opts := protojson.MarshalOptions{
		UseProtoNames:   true,
		AllowPartial:    true,
		EmitUnpopulated: false,
		Indent:          "  ",
	}
	data, err := opts.Marshal(m.obj.msg())
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (m *unMarshalversion) FromJson(value string) error {
	opts := protojson.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: false,
	}
	if value == "" {
		value = "{}"
	}
	uError := opts.Unmarshal([]byte(value), m.obj.msg())
	if uError != nil {
		return fmt.Errorf("unmarshal error %s", strings.Replace(
			uError.Error(), "\u00a0", " ", -1)[7:])
	}

	err := m.obj.validateToAndFrom()
	if err != nil {
		return err
	}
	return nil
}

func (obj *version) validateToAndFrom() error {
	// emptyVars()
	obj.validateObj(&obj.validation, true)
	return obj.validationResult()
}

func (obj *version) validate() error {
	// emptyVars()
	obj.validateObj(&obj.validation, false)
	return obj.validationResult()
}

func (obj *version) String() string {
	str, err := obj.Marshal().ToYaml()
	if err != nil {
		return err.Error()
	}
	return str
}

func (obj *version) Clone() (Version, error) {
	vErr := obj.validate()
	if vErr != nil {
		return nil, vErr
	}
	newObj := NewVersion()
	data, err := proto.Marshal(obj.msg())
	if err != nil {
		return nil, err
	}
	pbErr := proto.Unmarshal(data, newObj.msg())
	if pbErr != nil {
		return nil, pbErr
	}
	return newObj, nil
}

// Version is version details
type Version interface {
	Validation
	// msg marshals Version to protobuf object *l1s_pb.Version
	// and doesn't set defaults
	msg() *l1s_pb.Version
	// setMsg unmarshals Version from protobuf object *l1s_pb.Version
	// and doesn't set defaults
	setMsg(*l1s_pb.Version) Version
	// provides marshal interface
	Marshal() marshalVersion
	// provides unmarshal interface
	Unmarshal() unMarshalVersion
	// validate validates Version
	validate() error
	// A stringer function
	String() string
	// Clones the object
	Clone() (Version, error)
	validateToAndFrom() error
	validateObj(vObj *validation, set_default bool)
	setDefault()
	// ApiSpecVersion returns string, set in Version.
	ApiSpecVersion() string
	// SetApiSpecVersion assigns string provided by user to Version
	SetApiSpecVersion(value string) Version
	// HasApiSpecVersion checks if ApiSpecVersion has been set in Version
	HasApiSpecVersion() bool
	// SdkVersion returns string, set in Version.
	SdkVersion() string
	// SetSdkVersion assigns string provided by user to Version
	SetSdkVersion(value string) Version
	// HasSdkVersion checks if SdkVersion has been set in Version
	HasSdkVersion() bool
	// AppVersion returns string, set in Version.
	AppVersion() string
	// SetAppVersion assigns string provided by user to Version
	SetAppVersion(value string) Version
	// HasAppVersion checks if AppVersion has been set in Version
	HasAppVersion() bool
}

// Version of API specification
// ApiSpecVersion returns a string
func (obj *version) ApiSpecVersion() string {

	return *obj.obj.ApiSpecVersion

}

// Version of API specification
// ApiSpecVersion returns a string
func (obj *version) HasApiSpecVersion() bool {
	return obj.obj.ApiSpecVersion != nil
}

// Version of API specification
// SetApiSpecVersion sets the string value in the Version object
func (obj *version) SetApiSpecVersion(value string) Version {

	obj.obj.ApiSpecVersion = &value
	return obj
}

// Version of SDK generated from API specification
// SdkVersion returns a string
func (obj *version) SdkVersion() string {

	return *obj.obj.SdkVersion

}

// Version of SDK generated from API specification
// SdkVersion returns a string
func (obj *version) HasSdkVersion() bool {
	return obj.obj.SdkVersion != nil
}

// Version of SDK generated from API specification
// SetSdkVersion sets the string value in the Version object
func (obj *version) SetSdkVersion(value string) Version {

	obj.obj.SdkVersion = &value
	return obj
}

// Version of application consuming or serving the API
// AppVersion returns a string
func (obj *version) AppVersion() string {

	return *obj.obj.AppVersion

}

// Version of application consuming or serving the API
// AppVersion returns a string
func (obj *version) HasAppVersion() bool {
	return obj.obj.AppVersion != nil
}

// Version of application consuming or serving the API
// SetAppVersion sets the string value in the Version object
func (obj *version) SetAppVersion(value string) Version {

	obj.obj.AppVersion = &value
	return obj
}

func (obj *version) validateObj(vObj *validation, set_default bool) {
	if set_default {
		obj.setDefault()
	}

}

func (obj *version) setDefault() {
	if obj.obj.ApiSpecVersion == nil {
		obj.SetApiSpecVersion("")
	}
	if obj.obj.SdkVersion == nil {
		obj.SetSdkVersion("")
	}
	if obj.obj.AppVersion == nil {
		obj.SetAppVersion("")
	}

}
