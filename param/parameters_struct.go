// Code generated by go generate; DO NOT EDIT.
/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package param

import (
	"time"
)

type Config struct {
	Cache struct {
		Concurrency int `mapstructure:"concurrency"`
		DataLocation string `mapstructure:"datalocation"`
		DataLocations []string `mapstructure:"datalocations"`
		EnableLotman bool `mapstructure:"enablelotman"`
		EnableOIDC bool `mapstructure:"enableoidc"`
		EnableVoms bool `mapstructure:"enablevoms"`
		ExportLocation string `mapstructure:"exportlocation"`
		HighWaterMark string `mapstructure:"highwatermark"`
		LocalRoot string `mapstructure:"localroot"`
		LowWatermark string `mapstructure:"lowwatermark"`
		MetaLocations []string `mapstructure:"metalocations"`
		PermittedNamespaces []string `mapstructure:"permittednamespaces"`
		Port int `mapstructure:"port"`
		RunLocation string `mapstructure:"runlocation"`
		SelfTest bool `mapstructure:"selftest"`
		SelfTestInterval time.Duration `mapstructure:"selftestinterval"`
		SentinelLocation string `mapstructure:"sentinellocation"`
		Url string `mapstructure:"url"`
		XRootDPrefix string `mapstructure:"xrootdprefix"`
	} `mapstructure:"cache"`
	Client struct {
		AssumeDirectorServerHeader bool `mapstructure:"assumedirectorserverheader"`
		DisableHttpProxy bool `mapstructure:"disablehttpproxy"`
		DisableProxyFallback bool `mapstructure:"disableproxyfallback"`
		MaximumDownloadSpeed int `mapstructure:"maximumdownloadspeed"`
		MinimumDownloadSpeed int `mapstructure:"minimumdownloadspeed"`
		SlowTransferRampupTime time.Duration `mapstructure:"slowtransferrampuptime"`
		SlowTransferWindow time.Duration `mapstructure:"slowtransferwindow"`
		StoppedTransferTimeout time.Duration `mapstructure:"stoppedtransfertimeout"`
		WorkerCount int `mapstructure:"workercount"`
	} `mapstructure:"client"`
	ConfigDir string `mapstructure:"configdir"`
	ConfigLocations []string `mapstructure:"configlocations"`
	Debug bool `mapstructure:"debug"`
	Director struct {
		AdvertisementTTL time.Duration `mapstructure:"advertisementttl"`
		CacheResponseHostnames []string `mapstructure:"cacheresponsehostnames"`
		CacheSortMethod string `mapstructure:"cachesortmethod"`
		CachesPullFromCaches bool `mapstructure:"cachespullfromcaches"`
		DefaultResponse string `mapstructure:"defaultresponse"`
		EnableBroker bool `mapstructure:"enablebroker"`
		EnableOIDC bool `mapstructure:"enableoidc"`
		EnableStat bool `mapstructure:"enablestat"`
		FilteredServers []string `mapstructure:"filteredservers"`
		GeoIPLocation string `mapstructure:"geoiplocation"`
		MaxMindKeyFile string `mapstructure:"maxmindkeyfile"`
		MaxStatResponse int `mapstructure:"maxstatresponse"`
		MinStatResponse int `mapstructure:"minstatresponse"`
		OriginCacheHealthTestInterval time.Duration `mapstructure:"origincachehealthtestinterval"`
		OriginResponseHostnames []string `mapstructure:"originresponsehostnames"`
		StatConcurrencyLimit int `mapstructure:"statconcurrencylimit"`
		StatTimeout time.Duration `mapstructure:"stattimeout"`
		SupportContactEmail string `mapstructure:"supportcontactemail"`
		SupportContactUrl string `mapstructure:"supportcontacturl"`
	} `mapstructure:"director"`
	DisableHttpProxy bool `mapstructure:"disablehttpproxy"`
	DisableProxyFallback bool `mapstructure:"disableproxyfallback"`
	Federation struct {
		BrokerUrl string `mapstructure:"brokerurl"`
		DirectorUrl string `mapstructure:"directorurl"`
		DiscoveryUrl string `mapstructure:"discoveryurl"`
		JwkUrl string `mapstructure:"jwkurl"`
		RegistryUrl string `mapstructure:"registryurl"`
		TopologyNamespaceUrl string `mapstructure:"topologynamespaceurl"`
		TopologyReloadInterval time.Duration `mapstructure:"topologyreloadinterval"`
		TopologyUrl string `mapstructure:"topologyurl"`
	} `mapstructure:"federation"`
	GeoIPOverrides interface{} `mapstructure:"geoipoverrides"`
	Issuer struct {
		AuthenticationSource string `mapstructure:"authenticationsource"`
		AuthorizationTemplates interface{} `mapstructure:"authorizationtemplates"`
		GroupFile string `mapstructure:"groupfile"`
		GroupRequirements []string `mapstructure:"grouprequirements"`
		GroupSource string `mapstructure:"groupsource"`
		IssuerClaimValue string `mapstructure:"issuerclaimvalue"`
		OIDCAuthenticationRequirements interface{} `mapstructure:"oidcauthenticationrequirements"`
		OIDCAuthenticationUserClaim string `mapstructure:"oidcauthenticationuserclaim"`
		OIDCGroupClaim string `mapstructure:"oidcgroupclaim"`
		QDLLocation string `mapstructure:"qdllocation"`
		ScitokensServerLocation string `mapstructure:"scitokensserverlocation"`
		TomcatLocation string `mapstructure:"tomcatlocation"`
		UserStripDomain bool `mapstructure:"userstripdomain"`
	} `mapstructure:"issuer"`
	IssuerKey string `mapstructure:"issuerkey"`
	LocalCache struct {
		DataLocation string `mapstructure:"datalocation"`
		HighWaterMarkPercentage int `mapstructure:"highwatermarkpercentage"`
		LowWaterMarkPercentage int `mapstructure:"lowwatermarkpercentage"`
		RunLocation string `mapstructure:"runlocation"`
		Size string `mapstructure:"size"`
		Socket string `mapstructure:"socket"`
	} `mapstructure:"localcache"`
	Logging struct {
		Cache struct {
			Http string `mapstructure:"http"`
			Ofs string `mapstructure:"ofs"`
			Pfc string `mapstructure:"pfc"`
			Pss string `mapstructure:"pss"`
			Scitokens string `mapstructure:"scitokens"`
			Xrd string `mapstructure:"xrd"`
			Xrootd string `mapstructure:"xrootd"`
		} `mapstructure:"cache"`
		DisableProgressBars bool `mapstructure:"disableprogressbars"`
		Level string `mapstructure:"level"`
		LogLocation string `mapstructure:"loglocation"`
		Origin struct {
			Cms string `mapstructure:"cms"`
			Http string `mapstructure:"http"`
			Ofs string `mapstructure:"ofs"`
			Oss string `mapstructure:"oss"`
			Scitokens string `mapstructure:"scitokens"`
			Xrd string `mapstructure:"xrd"`
			Xrootd string `mapstructure:"xrootd"`
		} `mapstructure:"origin"`
	} `mapstructure:"logging"`
	Lotman struct {
		DbLocation string `mapstructure:"dblocation"`
		EnableAPI bool `mapstructure:"enableapi"`
		LibLocation string `mapstructure:"liblocation"`
		Lots interface{} `mapstructure:"lots"`
	} `mapstructure:"lotman"`
	MinimumDownloadSpeed int `mapstructure:"minimumdownloadspeed"`
	Monitoring struct {
		AggregatePrefixes []string `mapstructure:"aggregateprefixes"`
		DataLocation string `mapstructure:"datalocation"`
		MetricAuthorization bool `mapstructure:"metricauthorization"`
		PortHigher int `mapstructure:"porthigher"`
		PortLower int `mapstructure:"portlower"`
		PromQLAuthorization bool `mapstructure:"promqlauthorization"`
		TokenExpiresIn time.Duration `mapstructure:"tokenexpiresin"`
		TokenRefreshInterval time.Duration `mapstructure:"tokenrefreshinterval"`
	} `mapstructure:"monitoring"`
	OIDC struct {
		AuthorizationEndpoint string `mapstructure:"authorizationendpoint"`
		ClientID string `mapstructure:"clientid"`
		ClientIDFile string `mapstructure:"clientidfile"`
		ClientRedirectHostname string `mapstructure:"clientredirecthostname"`
		ClientSecretFile string `mapstructure:"clientsecretfile"`
		DeviceAuthEndpoint string `mapstructure:"deviceauthendpoint"`
		Issuer string `mapstructure:"issuer"`
		TokenEndpoint string `mapstructure:"tokenendpoint"`
		UserInfoEndpoint string `mapstructure:"userinfoendpoint"`
	} `mapstructure:"oidc"`
	Origin struct {
		DbLocation string `mapstructure:"dblocation"`
		DirectorTest bool `mapstructure:"directortest"`
		EnableBroker bool `mapstructure:"enablebroker"`
		EnableCmsd bool `mapstructure:"enablecmsd"`
		EnableDirListing bool `mapstructure:"enabledirlisting"`
		EnableDirectReads bool `mapstructure:"enabledirectreads"`
		EnableFallbackRead bool `mapstructure:"enablefallbackread"`
		EnableIssuer bool `mapstructure:"enableissuer"`
		EnableListings bool `mapstructure:"enablelistings"`
		EnableMacaroons bool `mapstructure:"enablemacaroons"`
		EnableOIDC bool `mapstructure:"enableoidc"`
		EnablePublicReads bool `mapstructure:"enablepublicreads"`
		EnableReads bool `mapstructure:"enablereads"`
		EnableUI bool `mapstructure:"enableui"`
		EnableVoms bool `mapstructure:"enablevoms"`
		EnableWrite bool `mapstructure:"enablewrite"`
		EnableWrites bool `mapstructure:"enablewrites"`
		ExportVolume string `mapstructure:"exportvolume"`
		ExportVolumes []string `mapstructure:"exportvolumes"`
		Exports interface{} `mapstructure:"exports"`
		FederationPrefix string `mapstructure:"federationprefix"`
		GlobusClientIDFile string `mapstructure:"globusclientidfile"`
		GlobusClientSecretFile string `mapstructure:"globusclientsecretfile"`
		GlobusCollectionID string `mapstructure:"globuscollectionid"`
		GlobusCollectionName string `mapstructure:"globuscollectionname"`
		GlobusConfigLocation string `mapstructure:"globusconfiglocation"`
		HttpAuthTokenFile string `mapstructure:"httpauthtokenfile"`
		HttpServiceUrl string `mapstructure:"httpserviceurl"`
		Mode string `mapstructure:"mode"`
		Multiuser bool `mapstructure:"multiuser"`
		NamespacePrefix string `mapstructure:"namespaceprefix"`
		Port int `mapstructure:"port"`
		RunLocation string `mapstructure:"runlocation"`
		S3AccessKeyfile string `mapstructure:"s3accesskeyfile"`
		S3Bucket string `mapstructure:"s3bucket"`
		S3Region string `mapstructure:"s3region"`
		S3SecretKeyfile string `mapstructure:"s3secretkeyfile"`
		S3ServiceName string `mapstructure:"s3servicename"`
		S3ServiceUrl string `mapstructure:"s3serviceurl"`
		S3UrlStyle string `mapstructure:"s3urlstyle"`
		ScitokensDefaultUser string `mapstructure:"scitokensdefaultuser"`
		ScitokensMapSubject bool `mapstructure:"scitokensmapsubject"`
		ScitokensNameMapFile string `mapstructure:"scitokensnamemapfile"`
		ScitokensRestrictedPaths []string `mapstructure:"scitokensrestrictedpaths"`
		ScitokensUsernameClaim string `mapstructure:"scitokensusernameclaim"`
		SelfTest bool `mapstructure:"selftest"`
		SelfTestInterval time.Duration `mapstructure:"selftestinterval"`
		StoragePrefix string `mapstructure:"storageprefix"`
		StorageType string `mapstructure:"storagetype"`
		Url string `mapstructure:"url"`
		XRootDPrefix string `mapstructure:"xrootdprefix"`
		XRootServiceUrl string `mapstructure:"xrootserviceurl"`
	} `mapstructure:"origin"`
	Plugin struct {
		Token string `mapstructure:"token"`
	} `mapstructure:"plugin"`
	Registry struct {
		AdminUsers []string `mapstructure:"adminusers"`
		CustomRegistrationFields interface{} `mapstructure:"customregistrationfields"`
		DbLocation string `mapstructure:"dblocation"`
		Institutions interface{} `mapstructure:"institutions"`
		InstitutionsUrl string `mapstructure:"institutionsurl"`
		InstitutionsUrlReloadMinutes time.Duration `mapstructure:"institutionsurlreloadminutes"`
		RequireCacheApproval bool `mapstructure:"requirecacheapproval"`
		RequireKeyChaining bool `mapstructure:"requirekeychaining"`
		RequireOriginApproval bool `mapstructure:"requireoriginapproval"`
	} `mapstructure:"registry"`
	Server struct {
		EnablePprof bool `mapstructure:"enablepprof"`
		EnableUI bool `mapstructure:"enableui"`
		ExternalWebUrl string `mapstructure:"externalweburl"`
		Hostname string `mapstructure:"hostname"`
		IssuerHostname string `mapstructure:"issuerhostname"`
		IssuerJwks string `mapstructure:"issuerjwks"`
		IssuerPort int `mapstructure:"issuerport"`
		IssuerUrl string `mapstructure:"issuerurl"`
		Modules []string `mapstructure:"modules"`
		RegistrationRetryInterval time.Duration `mapstructure:"registrationretryinterval"`
		SessionSecretFile string `mapstructure:"sessionsecretfile"`
		StartupTimeout time.Duration `mapstructure:"startuptimeout"`
		TLSCACertificateDirectory string `mapstructure:"tlscacertificatedirectory"`
		TLSCACertificateFile string `mapstructure:"tlscacertificatefile"`
		TLSCAKey string `mapstructure:"tlscakey"`
		TLSCertificate string `mapstructure:"tlscertificate"`
		TLSKey string `mapstructure:"tlskey"`
		UIActivationCodeFile string `mapstructure:"uiactivationcodefile"`
		UIAdminUsers []string `mapstructure:"uiadminusers"`
		UILoginRateLimit int `mapstructure:"uiloginratelimit"`
		UIPasswordFile string `mapstructure:"uipasswordfile"`
		WebConfigFile string `mapstructure:"webconfigfile"`
		WebHost string `mapstructure:"webhost"`
		WebPort int `mapstructure:"webport"`
	} `mapstructure:"server"`
	Shoveler struct {
		AMQPExchange string `mapstructure:"amqpexchange"`
		AMQPTokenLocation string `mapstructure:"amqptokenlocation"`
		Enable bool `mapstructure:"enable"`
		IPMapping interface{} `mapstructure:"ipmapping"`
		MessageQueueProtocol string `mapstructure:"messagequeueprotocol"`
		OutputDestinations []string `mapstructure:"outputdestinations"`
		PortHigher int `mapstructure:"porthigher"`
		PortLower int `mapstructure:"portlower"`
		QueueDirectory string `mapstructure:"queuedirectory"`
		StompCert string `mapstructure:"stompcert"`
		StompCertKey string `mapstructure:"stompcertkey"`
		StompPassword string `mapstructure:"stomppassword"`
		StompUsername string `mapstructure:"stompusername"`
		Topic string `mapstructure:"topic"`
		URL string `mapstructure:"url"`
		VerifyHeader bool `mapstructure:"verifyheader"`
	} `mapstructure:"shoveler"`
	StagePlugin struct {
		Hook bool `mapstructure:"hook"`
		MountPrefix string `mapstructure:"mountprefix"`
		OriginPrefix string `mapstructure:"originprefix"`
		ShadowOriginPrefix string `mapstructure:"shadoworiginprefix"`
	} `mapstructure:"stageplugin"`
	TLSSkipVerify bool `mapstructure:"tlsskipverify"`
	Transport struct {
		DialerKeepAlive time.Duration `mapstructure:"dialerkeepalive"`
		DialerTimeout time.Duration `mapstructure:"dialertimeout"`
		ExpectContinueTimeout time.Duration `mapstructure:"expectcontinuetimeout"`
		IdleConnTimeout time.Duration `mapstructure:"idleconntimeout"`
		MaxIdleConns int `mapstructure:"maxidleconns"`
		ResponseHeaderTimeout time.Duration `mapstructure:"responseheadertimeout"`
		TLSHandshakeTimeout time.Duration `mapstructure:"tlshandshaketimeout"`
	} `mapstructure:"transport"`
	Xrootd struct {
		AuthRefreshInterval time.Duration `mapstructure:"authrefreshinterval"`
		Authfile string `mapstructure:"authfile"`
		ConfigFile string `mapstructure:"configfile"`
		DetailedMonitoringHost string `mapstructure:"detailedmonitoringhost"`
		DetailedMonitoringPort int `mapstructure:"detailedmonitoringport"`
		LocalMonitoringHost string `mapstructure:"localmonitoringhost"`
		MacaroonsKeyFile string `mapstructure:"macaroonskeyfile"`
		ManagerHost string `mapstructure:"managerhost"`
		ManagerPort int `mapstructure:"managerport"`
		Mount string `mapstructure:"mount"`
		Port int `mapstructure:"port"`
		RobotsTxtFile string `mapstructure:"robotstxtfile"`
		RunLocation string `mapstructure:"runlocation"`
		ScitokensConfig string `mapstructure:"scitokensconfig"`
		Sitename string `mapstructure:"sitename"`
		SummaryMonitoringHost string `mapstructure:"summarymonitoringhost"`
		SummaryMonitoringPort int `mapstructure:"summarymonitoringport"`
	} `mapstructure:"xrootd"`
}


type configWithType struct {
	Cache struct {
		Concurrency struct { Type string; Value int }
		DataLocation struct { Type string; Value string }
		DataLocations struct { Type string; Value []string }
		EnableLotman struct { Type string; Value bool }
		EnableOIDC struct { Type string; Value bool }
		EnableVoms struct { Type string; Value bool }
		ExportLocation struct { Type string; Value string }
		HighWaterMark struct { Type string; Value string }
		LocalRoot struct { Type string; Value string }
		LowWatermark struct { Type string; Value string }
		MetaLocations struct { Type string; Value []string }
		PermittedNamespaces struct { Type string; Value []string }
		Port struct { Type string; Value int }
		RunLocation struct { Type string; Value string }
		SelfTest struct { Type string; Value bool }
		SelfTestInterval struct { Type string; Value time.Duration }
		SentinelLocation struct { Type string; Value string }
		Url struct { Type string; Value string }
		XRootDPrefix struct { Type string; Value string }
	}
	Client struct {
		AssumeDirectorServerHeader struct { Type string; Value bool }
		DisableHttpProxy struct { Type string; Value bool }
		DisableProxyFallback struct { Type string; Value bool }
		MaximumDownloadSpeed struct { Type string; Value int }
		MinimumDownloadSpeed struct { Type string; Value int }
		SlowTransferRampupTime struct { Type string; Value time.Duration }
		SlowTransferWindow struct { Type string; Value time.Duration }
		StoppedTransferTimeout struct { Type string; Value time.Duration }
		WorkerCount struct { Type string; Value int }
	}
	ConfigDir struct { Type string; Value string }
	ConfigLocations struct { Type string; Value []string }
	Debug struct { Type string; Value bool }
	Director struct {
		AdvertisementTTL struct { Type string; Value time.Duration }
		CacheResponseHostnames struct { Type string; Value []string }
		CacheSortMethod struct { Type string; Value string }
		CachesPullFromCaches struct { Type string; Value bool }
		DefaultResponse struct { Type string; Value string }
		EnableBroker struct { Type string; Value bool }
		EnableOIDC struct { Type string; Value bool }
		EnableStat struct { Type string; Value bool }
		FilteredServers struct { Type string; Value []string }
		GeoIPLocation struct { Type string; Value string }
		MaxMindKeyFile struct { Type string; Value string }
		MaxStatResponse struct { Type string; Value int }
		MinStatResponse struct { Type string; Value int }
		OriginCacheHealthTestInterval struct { Type string; Value time.Duration }
		OriginResponseHostnames struct { Type string; Value []string }
		StatConcurrencyLimit struct { Type string; Value int }
		StatTimeout struct { Type string; Value time.Duration }
		SupportContactEmail struct { Type string; Value string }
		SupportContactUrl struct { Type string; Value string }
	}
	DisableHttpProxy struct { Type string; Value bool }
	DisableProxyFallback struct { Type string; Value bool }
	Federation struct {
		BrokerUrl struct { Type string; Value string }
		DirectorUrl struct { Type string; Value string }
		DiscoveryUrl struct { Type string; Value string }
		JwkUrl struct { Type string; Value string }
		RegistryUrl struct { Type string; Value string }
		TopologyNamespaceUrl struct { Type string; Value string }
		TopologyReloadInterval struct { Type string; Value time.Duration }
		TopologyUrl struct { Type string; Value string }
	}
	GeoIPOverrides struct { Type string; Value interface{} }
	Issuer struct {
		AuthenticationSource struct { Type string; Value string }
		AuthorizationTemplates struct { Type string; Value interface{} }
		GroupFile struct { Type string; Value string }
		GroupRequirements struct { Type string; Value []string }
		GroupSource struct { Type string; Value string }
		IssuerClaimValue struct { Type string; Value string }
		OIDCAuthenticationRequirements struct { Type string; Value interface{} }
		OIDCAuthenticationUserClaim struct { Type string; Value string }
		OIDCGroupClaim struct { Type string; Value string }
		QDLLocation struct { Type string; Value string }
		ScitokensServerLocation struct { Type string; Value string }
		TomcatLocation struct { Type string; Value string }
		UserStripDomain struct { Type string; Value bool }
	}
	IssuerKey struct { Type string; Value string }
	LocalCache struct {
		DataLocation struct { Type string; Value string }
		HighWaterMarkPercentage struct { Type string; Value int }
		LowWaterMarkPercentage struct { Type string; Value int }
		RunLocation struct { Type string; Value string }
		Size struct { Type string; Value string }
		Socket struct { Type string; Value string }
	}
	Logging struct {
		Cache struct {
			Http struct { Type string; Value string }
			Ofs struct { Type string; Value string }
			Pfc struct { Type string; Value string }
			Pss struct { Type string; Value string }
			Scitokens struct { Type string; Value string }
			Xrd struct { Type string; Value string }
			Xrootd struct { Type string; Value string }
		}
		DisableProgressBars struct { Type string; Value bool }
		Level struct { Type string; Value string }
		LogLocation struct { Type string; Value string }
		Origin struct {
			Cms struct { Type string; Value string }
			Http struct { Type string; Value string }
			Ofs struct { Type string; Value string }
			Oss struct { Type string; Value string }
			Scitokens struct { Type string; Value string }
			Xrd struct { Type string; Value string }
			Xrootd struct { Type string; Value string }
		}
	}
	Lotman struct {
		DbLocation struct { Type string; Value string }
		EnableAPI struct { Type string; Value bool }
		LibLocation struct { Type string; Value string }
		Lots struct { Type string; Value interface{} }
	}
	MinimumDownloadSpeed struct { Type string; Value int }
	Monitoring struct {
		AggregatePrefixes struct { Type string; Value []string }
		DataLocation struct { Type string; Value string }
		MetricAuthorization struct { Type string; Value bool }
		PortHigher struct { Type string; Value int }
		PortLower struct { Type string; Value int }
		PromQLAuthorization struct { Type string; Value bool }
		TokenExpiresIn struct { Type string; Value time.Duration }
		TokenRefreshInterval struct { Type string; Value time.Duration }
	}
	OIDC struct {
		AuthorizationEndpoint struct { Type string; Value string }
		ClientID struct { Type string; Value string }
		ClientIDFile struct { Type string; Value string }
		ClientRedirectHostname struct { Type string; Value string }
		ClientSecretFile struct { Type string; Value string }
		DeviceAuthEndpoint struct { Type string; Value string }
		Issuer struct { Type string; Value string }
		TokenEndpoint struct { Type string; Value string }
		UserInfoEndpoint struct { Type string; Value string }
	}
	Origin struct {
		DbLocation struct { Type string; Value string }
		DirectorTest struct { Type string; Value bool }
		EnableBroker struct { Type string; Value bool }
		EnableCmsd struct { Type string; Value bool }
		EnableDirListing struct { Type string; Value bool }
		EnableDirectReads struct { Type string; Value bool }
		EnableFallbackRead struct { Type string; Value bool }
		EnableIssuer struct { Type string; Value bool }
		EnableListings struct { Type string; Value bool }
		EnableMacaroons struct { Type string; Value bool }
		EnableOIDC struct { Type string; Value bool }
		EnablePublicReads struct { Type string; Value bool }
		EnableReads struct { Type string; Value bool }
		EnableUI struct { Type string; Value bool }
		EnableVoms struct { Type string; Value bool }
		EnableWrite struct { Type string; Value bool }
		EnableWrites struct { Type string; Value bool }
		ExportVolume struct { Type string; Value string }
		ExportVolumes struct { Type string; Value []string }
		Exports struct { Type string; Value interface{} }
		FederationPrefix struct { Type string; Value string }
		GlobusClientIDFile struct { Type string; Value string }
		GlobusClientSecretFile struct { Type string; Value string }
		GlobusCollectionID struct { Type string; Value string }
		GlobusCollectionName struct { Type string; Value string }
		GlobusConfigLocation struct { Type string; Value string }
		HttpAuthTokenFile struct { Type string; Value string }
		HttpServiceUrl struct { Type string; Value string }
		Mode struct { Type string; Value string }
		Multiuser struct { Type string; Value bool }
		NamespacePrefix struct { Type string; Value string }
		Port struct { Type string; Value int }
		RunLocation struct { Type string; Value string }
		S3AccessKeyfile struct { Type string; Value string }
		S3Bucket struct { Type string; Value string }
		S3Region struct { Type string; Value string }
		S3SecretKeyfile struct { Type string; Value string }
		S3ServiceName struct { Type string; Value string }
		S3ServiceUrl struct { Type string; Value string }
		S3UrlStyle struct { Type string; Value string }
		ScitokensDefaultUser struct { Type string; Value string }
		ScitokensMapSubject struct { Type string; Value bool }
		ScitokensNameMapFile struct { Type string; Value string }
		ScitokensRestrictedPaths struct { Type string; Value []string }
		ScitokensUsernameClaim struct { Type string; Value string }
		SelfTest struct { Type string; Value bool }
		SelfTestInterval struct { Type string; Value time.Duration }
		StoragePrefix struct { Type string; Value string }
		StorageType struct { Type string; Value string }
		Url struct { Type string; Value string }
		XRootDPrefix struct { Type string; Value string }
		XRootServiceUrl struct { Type string; Value string }
	}
	Plugin struct {
		Token struct { Type string; Value string }
	}
	Registry struct {
		AdminUsers struct { Type string; Value []string }
		CustomRegistrationFields struct { Type string; Value interface{} }
		DbLocation struct { Type string; Value string }
		Institutions struct { Type string; Value interface{} }
		InstitutionsUrl struct { Type string; Value string }
		InstitutionsUrlReloadMinutes struct { Type string; Value time.Duration }
		RequireCacheApproval struct { Type string; Value bool }
		RequireKeyChaining struct { Type string; Value bool }
		RequireOriginApproval struct { Type string; Value bool }
	}
	Server struct {
		EnablePprof struct { Type string; Value bool }
		EnableUI struct { Type string; Value bool }
		ExternalWebUrl struct { Type string; Value string }
		Hostname struct { Type string; Value string }
		IssuerHostname struct { Type string; Value string }
		IssuerJwks struct { Type string; Value string }
		IssuerPort struct { Type string; Value int }
		IssuerUrl struct { Type string; Value string }
		Modules struct { Type string; Value []string }
		RegistrationRetryInterval struct { Type string; Value time.Duration }
		SessionSecretFile struct { Type string; Value string }
		StartupTimeout struct { Type string; Value time.Duration }
		TLSCACertificateDirectory struct { Type string; Value string }
		TLSCACertificateFile struct { Type string; Value string }
		TLSCAKey struct { Type string; Value string }
		TLSCertificate struct { Type string; Value string }
		TLSKey struct { Type string; Value string }
		UIActivationCodeFile struct { Type string; Value string }
		UIAdminUsers struct { Type string; Value []string }
		UILoginRateLimit struct { Type string; Value int }
		UIPasswordFile struct { Type string; Value string }
		WebConfigFile struct { Type string; Value string }
		WebHost struct { Type string; Value string }
		WebPort struct { Type string; Value int }
	}
	Shoveler struct {
		AMQPExchange struct { Type string; Value string }
		AMQPTokenLocation struct { Type string; Value string }
		Enable struct { Type string; Value bool }
		IPMapping struct { Type string; Value interface{} }
		MessageQueueProtocol struct { Type string; Value string }
		OutputDestinations struct { Type string; Value []string }
		PortHigher struct { Type string; Value int }
		PortLower struct { Type string; Value int }
		QueueDirectory struct { Type string; Value string }
		StompCert struct { Type string; Value string }
		StompCertKey struct { Type string; Value string }
		StompPassword struct { Type string; Value string }
		StompUsername struct { Type string; Value string }
		Topic struct { Type string; Value string }
		URL struct { Type string; Value string }
		VerifyHeader struct { Type string; Value bool }
	}
	StagePlugin struct {
		Hook struct { Type string; Value bool }
		MountPrefix struct { Type string; Value string }
		OriginPrefix struct { Type string; Value string }
		ShadowOriginPrefix struct { Type string; Value string }
	}
	TLSSkipVerify struct { Type string; Value bool }
	Transport struct {
		DialerKeepAlive struct { Type string; Value time.Duration }
		DialerTimeout struct { Type string; Value time.Duration }
		ExpectContinueTimeout struct { Type string; Value time.Duration }
		IdleConnTimeout struct { Type string; Value time.Duration }
		MaxIdleConns struct { Type string; Value int }
		ResponseHeaderTimeout struct { Type string; Value time.Duration }
		TLSHandshakeTimeout struct { Type string; Value time.Duration }
	}
	Xrootd struct {
		AuthRefreshInterval struct { Type string; Value time.Duration }
		Authfile struct { Type string; Value string }
		ConfigFile struct { Type string; Value string }
		DetailedMonitoringHost struct { Type string; Value string }
		DetailedMonitoringPort struct { Type string; Value int }
		LocalMonitoringHost struct { Type string; Value string }
		MacaroonsKeyFile struct { Type string; Value string }
		ManagerHost struct { Type string; Value string }
		ManagerPort struct { Type string; Value int }
		Mount struct { Type string; Value string }
		Port struct { Type string; Value int }
		RobotsTxtFile struct { Type string; Value string }
		RunLocation struct { Type string; Value string }
		ScitokensConfig struct { Type string; Value string }
		Sitename struct { Type string; Value string }
		SummaryMonitoringHost struct { Type string; Value string }
		SummaryMonitoringPort struct { Type string; Value int }
	}
}
