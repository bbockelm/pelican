//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

package xrootd

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pelicanplatform/pelican/cache_ui"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/origin_ui"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	//go:embed resources/test-scitokens-empty.cfg
	emptyOutput string

	//go:embed resources/test-scitokens-issuer.cfg
	simpleOutput string

	//go:embed resources/test-scitokens-2issuers.cfg
	dualOutput string

	// For now, this unit test uses the same input as the prior one;
	// duplicating the variable name to make it clear these are different
	// tests.
	//go:embed resources/test-scitokens-2issuers.cfg
	toMergeOutput string

	//go:embed resources/test-scitokens-monitoring.cfg
	monitoringOutput string

	//go:embed resources/test-scitokens-cache-issuer.cfg
	cacheSciOutput string

	//go:embed resources/test-scitokens-cache-empty.cfg
	cacheEmptyOutput string

	sampleMultilineOutput = `foo \
	bar
	baz
	abc \`

	sampleMultilineOutputParsed = []string{"foo \tbar", "\tbaz", "\tabc "}

	cacheAuthfileMultilineInput = `
u * /user/ligo -rl \
/Gluex rl \
/NSG/PUBLIC rl \
/VDC/PUBLIC rl`

	cacheAuthfileOutput = "u * /.well-known lr /user/ligo -rl /Gluex rl /NSG/PUBLIC rl /VDC/PUBLIC rl\n"

	// Configuration snippet from bug report #601
	scitokensCfgAud = `
[Global]
audience = GLOW, HCC, IceCube, NRP, OSG, PATh, UCSD

[Issuer https://ap20.uc.osg-htc.org:1094/ospool/ap20]
issuer = https://ap20.uc.osg-htc.org:1094/ospool/ap20
base_path = /ospool/ap20
`

	// Actual authfile entries here are from the bug report #568
	otherAuthfileEntries = `# DN: /CN=sc-origin.chtc.wisc.edu
u 5a42185a.0 /chtc/PROTECTED/sc-origin lr
# DN: /DC=org/DC=incommon/C=US/ST=California/O=University of California, San Diego/CN=osg-stash-sfu-computecanada-ca.nationalresearchplatform.org
u 4ff08838.0 /chtc/PROTECTED/sc-origin lr
# DN: /DC=org/DC=incommon/C=US/ST=Georgia/O=Georgia Institute of Technology/OU=Office of Information Technology/CN=osg-gftp2.pace.gatech.edu
u 3af6a420.0 /chtc/PROTECTED/sc-origin lr
`

	mergedAuthfileEntries = otherAuthfileEntries + "u * /.well-known lr\n"
)

func TestAuthfileMultiline(t *testing.T) {
	sc := bufio.NewScanner(strings.NewReader(sampleMultilineOutput))
	sc.Split(ScanLinesWithCont)
	idx := 0
	for sc.Scan() {
		require.Less(t, idx, len(sampleMultilineOutputParsed))
		assert.Equal(t, string(sampleMultilineOutputParsed[idx]), sc.Text())
		idx += 1
	}
	assert.Equal(t, idx, len(sampleMultilineOutputParsed))
}

func TestEmitAuthfile(t *testing.T) {
	tests := []struct {
		desc    string
		authIn  string
		authOut string
	}{
		{
			desc:    "merge-multi-lines",
			authIn:  cacheAuthfileMultilineInput,
			authOut: cacheAuthfileOutput,
		},
		{
			desc:    "merge-other-entries",
			authIn:  otherAuthfileEntries,
			authOut: mergedAuthfileEntries,
		},
	}
	for _, testInput := range tests {
		t.Run(testInput.desc, func(t *testing.T) {
			dirName := t.TempDir()
			viper.Reset()
			viper.Set("Xrootd.Authfile", filepath.Join(dirName, "authfile"))
			viper.Set("Xrootd.RunLocation", dirName)
			server := &origin_ui.OriginServer{}

			err := os.WriteFile(filepath.Join(dirName, "authfile"), []byte(testInput.authIn), fs.FileMode(0600))
			require.NoError(t, err)

			err = EmitAuthfile(server)
			require.NoError(t, err)

			contents, err := os.ReadFile(filepath.Join(dirName, "authfile-origin-generated"))
			require.NoError(t, err)

			assert.Equal(t, testInput.authOut, string(contents))
		})
	}
}

func TestEmitCfg(t *testing.T) {
	dirname := t.TempDir()
	viper.Reset()
	viper.Set("Xrootd.RunLocation", dirname)
	err := config.InitClient()
	assert.Nil(t, err)

	configTester := func(cfg *ScitokensCfg, configResult string) func(t *testing.T) {
		return func(t *testing.T) {
			err = writeScitokensConfiguration(config.OriginType, cfg)
			assert.NoError(t, err)

			genCfg, err := os.ReadFile(filepath.Join(dirname, "scitokens-origin-generated.cfg"))
			assert.NoError(t, err)

			assert.Equal(t, string(configResult), string(genCfg))
		}
	}

	globalCfg := GlobalCfg{Audience: []string{"test_audience"}}
	t.Run("EmptyConfig", configTester(&ScitokensCfg{Global: globalCfg}, emptyOutput))

	issuer := Issuer{Name: "Demo", Issuer: "https://demo.scitokens.org", BasePaths: []string{"/foo", "/bar"}, DefaultUser: "osg"}
	t.Run("SimpleIssuer", configTester(&ScitokensCfg{Global: globalCfg, IssuerMap: map[string]Issuer{issuer.Issuer: issuer}}, simpleOutput))
	issuer2 := Issuer{Name: "WLCG", Issuer: "https://wlcg.cnaf.infn.it", BasePaths: []string{"/baz"}}
	t.Run("DualIssuers", configTester(&ScitokensCfg{Global: globalCfg, IssuerMap: map[string]Issuer{issuer.Issuer: issuer, issuer2.Issuer: issuer2}}, dualOutput))
}

func TestLoadScitokensConfig(t *testing.T) {
	dirname := t.TempDir()
	viper.Reset()
	viper.Set("Xrootd.RunLocation", dirname)
	err := config.InitClient()
	assert.Nil(t, err)

	configTester := func(configResult string) func(t *testing.T) {
		return func(t *testing.T) {
			cfgFname := filepath.Join(dirname, "scitokens-test.cfg")
			err := os.WriteFile(cfgFname, []byte(configResult), 0600)
			require.NoError(t, err)

			cfg, err := LoadScitokensConfig(cfgFname)
			require.NoError(t, err)

			err = writeScitokensConfiguration(config.OriginType, &cfg)
			assert.NoError(t, err)

			genCfg, err := os.ReadFile(filepath.Join(dirname, "scitokens-origin-generated.cfg"))
			assert.NoError(t, err)

			assert.Equal(t, string(configResult), string(genCfg))
		}
	}

	t.Run("EmptyConfig", configTester(emptyOutput))
	t.Run("SimpleIssuer", configTester(simpleOutput))
	t.Run("DualIssuers", configTester(dualOutput))
}

// Test that merging the configuration works without throwing any errors
func TestMergeConfig(t *testing.T) {
	dirname := t.TempDir()
	viper.Reset()
	viper.Set("Xrootd.RunLocation", dirname)
	scitokensConfigFile := filepath.Join(dirname, "scitokens-input.cfg")
	viper.Set("Xrootd.ScitokensConfig", scitokensConfigFile)

	configTester := func(configInput string, postProcess func(*testing.T, ScitokensCfg)) func(t *testing.T) {
		return func(t *testing.T) {
			ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
			defer func() { require.NoError(t, egrp.Wait()) }()
			defer cancel()

			err := os.WriteFile(scitokensConfigFile, []byte(configInput), fs.FileMode(0600))
			require.NoError(t, err)

			err = config.InitServer(ctx, config.OriginType)
			require.NoError(t, err)

			err = EmitScitokensConfig(&origin_ui.OriginServer{})
			require.NoError(t, err)

			cfg, err := LoadScitokensConfig(filepath.Join(dirname, "scitokens-origin-generated.cfg"))
			require.NoError(t, err)

			postProcess(t, cfg)
		}
	}

	t.Run("AudienceNoJson", configTester(scitokensCfgAud, func(t *testing.T, cfg ScitokensCfg) {
		assert.True(t, reflect.DeepEqual([]string{"GLOW", "HCC", "IceCube", "NRP", "OSG", "PATh", "UCSD", param.Server_IssuerUrl.GetString()}, cfg.Global.Audience))
	}))
}

func TestGenerateConfig(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	viper.Reset()
	viper.Set("Origin.SelfTest", false)
	issuer, err := GenerateMonitoringIssuer()
	require.NoError(t, err)
	assert.Equal(t, issuer.Name, "")

	viper.Set("Origin.SelfTest", true)
	err = config.InitServer(ctx, config.OriginType)
	require.NoError(t, err)
	issuer, err = GenerateMonitoringIssuer()
	require.NoError(t, err)
	assert.Equal(t, issuer.Name, "Built-in Monitoring")
	assert.Equal(t, issuer.Issuer, "https://"+param.Server_Hostname.GetString()+":"+fmt.Sprint(param.Xrootd_Port.GetInt()))
	require.Equal(t, len(issuer.BasePaths), 1)
	assert.Equal(t, issuer.BasePaths[0], "/pelican/monitoring")
	assert.Equal(t, issuer.DefaultUser, "xrootd")

	viper.Reset()
	viper.Set("Origin.SelfTest", false)
	viper.Set("Origin.ScitokensDefaultUser", "user1")
	viper.Set("Origin.ScitokensMapSubject", true)
	err = config.InitServer(ctx, config.OriginType)
	require.NoError(t, err)
	issuer, err = GenerateOriginIssuer([]string{"/foo/bar/baz", "/another/exported/path"})
	require.NoError(t, err)
	assert.Equal(t, issuer.Name, "Origin")
	assert.Equal(t, issuer.Issuer, "https://"+param.Server_Hostname.GetString()+":"+fmt.Sprint(param.Xrootd_Port.GetInt()))
	require.Equal(t, len(issuer.BasePaths), 2)
	assert.Equal(t, issuer.BasePaths[0], "/foo/bar/baz")
	assert.Equal(t, issuer.BasePaths[1], "/another/exported/path")
	assert.Equal(t, issuer.DefaultUser, "user1")
	assert.Equal(t, issuer.MapSubject, true)
}

func TestWriteOriginAuthFiles(t *testing.T) {
	viper.Reset()
	originAuthTester := func(server server_utils.XRootDServer, authStart string, authResult string) func(t *testing.T) {
		return func(t *testing.T) {
			defer viper.Reset()
			dirname := t.TempDir()
			viper.Set("Xrootd.RunLocation", dirname)
			viper.Set("Xrootd.ScitokensConfig", filepath.Join(dirname, "scitokens-generated.cfg"))
			viper.Set("Xrootd.Authfile", filepath.Join(dirname, "authfile"))
			xAuthFile := filepath.Join(param.Xrootd_RunLocation.GetString(), "authfile-origin-generated")

			authfileProvided := param.Xrootd_Authfile.GetString()

			err := os.WriteFile(authfileProvided, []byte(authStart), 0600)
			assert.NoError(t, err)

			err = EmitAuthfile(server)
			assert.NoError(t, err)

			authGen, err := os.ReadFile(xAuthFile)
			assert.NoError(t, err)
			assert.Equal(t, authResult, string(authGen))
		}
	}
	nsAds := []director.NamespaceAdV2{}

	originServer := &origin_ui.OriginServer{}
	originServer.SetNamespaceAds(nsAds)

	t.Run("MultiIssuer", originAuthTester(originServer, "u * t1 lr t2 lr t3 lr", "u * /.well-known lr t1 lr t2 lr t3 lr\n"))

	nsAds = []director.NamespaceAdV2{}
	originServer.SetNamespaceAds(nsAds)

	t.Run("EmptyAuth", originAuthTester(originServer, "", "u * /.well-known lr\n"))

	viper.Set("Origin.EnablePublicReads", true)
	viper.Set("Origin.NamespacePrefix", "/foo/bar")
	t.Run("PublicAuth", originAuthTester(originServer, "", "u * /.well-known lr /foo/bar lr\n"))
}

func TestWriteCacheAuthFiles(t *testing.T) {

	cacheAuthTester := func(server server_utils.XRootDServer, sciTokenResult string, authResult string) func(t *testing.T) {
		return func(t *testing.T) {

			dirname := t.TempDir()
			viper.Reset()
			viper.Set("Xrootd.RunLocation", dirname)
			if server.GetServerType().IsEnabled(config.OriginType) {
				viper.Set("Xrootd.ScitokensConfig", filepath.Join(dirname, "scitokens-origin-generated.cfg"))
				viper.Set("Xrootd.Authfile", filepath.Join(dirname, "authfile-origin-generated"))
			} else {
				viper.Set("Xrootd.ScitokensConfig", filepath.Join(dirname, "scitokens-cache-generated.cfg"))
				viper.Set("Xrootd.Authfile", filepath.Join(dirname, "authfile-cache-generated"))
			}
			authFile := param.Xrootd_Authfile.GetString()
			err := os.WriteFile(authFile, []byte(""), 0600)
			assert.NoError(t, err)

			err = WriteCacheScitokensConfig(server.GetNamespaceAds())
			assert.NoError(t, err)

			sciFile := param.Xrootd_ScitokensConfig.GetString()
			genSciToken, err := os.ReadFile(sciFile)
			assert.NoError(t, err)

			assert.Equal(t, sciTokenResult, string(genSciToken))

			err = EmitAuthfile(server)
			assert.NoError(t, err)

			authGen, err := os.ReadFile(authFile)
			assert.NoError(t, err)
			assert.Equal(t, authResult, string(authGen))
		}
	}

	issuer1URL := url.URL{}
	issuer1URL.Scheme = "https"
	issuer1URL.Host = "issuer1.com"

	issuer2URL := url.URL{}
	issuer2URL.Scheme = "https"
	issuer2URL.Host = "issuer2.com"

	issuer3URL := url.URL{}
	issuer3URL.Scheme = "https"
	issuer3URL.Host = "issuer3.com"

	issuer4URL := url.URL{}
	issuer4URL.Scheme = "https"
	issuer4URL.Host = "issuer4.com"

	PublicCaps := director.Capabilities{
		PublicRead: true,
		Read:       true,
		Write:      true,
	}
	PrivateCaps := director.Capabilities{
		PublicRead: false,
		Read:       true,
		Write:      true,
	}

	nsAds := []director.NamespaceAdV2{
		{
			PublicRead: false,
			Caps:       PrivateCaps,
			Issuer: []director.TokenIssuer{{
				IssuerUrl: issuer1URL,
				BasePaths: []string{"/p1"},
			}},
		},
		{
			PublicRead: false,
			Caps:       PrivateCaps,
			Issuer: []director.TokenIssuer{{
				IssuerUrl: issuer2URL,
				BasePaths: []string{"/p2/path"},
			}},
		},
		{
			Path:       "/p3",
			PublicRead: true,
			Caps:       PublicCaps,
		},
		{
			PublicRead: false,
			Caps:       PrivateCaps,
			Issuer: []director.TokenIssuer{{
				IssuerUrl: issuer1URL,
				BasePaths: []string{"/p1_again"},
			}}},
		{
			Path:       "/p4/depth",
			PublicRead: true,
			Caps:       PublicCaps,
		},
		{
			Path:       "/p2_noauth",
			PublicRead: true,
			Caps:       PublicCaps,
		},
	}

	cacheServer := &cache_ui.CacheServer{}
	cacheServer.SetNamespaceAds(nsAds)

	t.Run("MultiIssuer", cacheAuthTester(cacheServer, cacheSciOutput, "u * /p3 lr /p4/depth lr /p2_noauth lr \n"))

	nsAds = []director.NamespaceAdV2{}
	cacheServer.SetNamespaceAds(nsAds)

	t.Run("EmptyNS", cacheAuthTester(cacheServer, cacheEmptyOutput, ""))
}

func TestWriteOriginScitokensConfig(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	viper.Reset()
	dirname := t.TempDir()
	os.Setenv("PELICAN_XROOTD_RUNLOCATION", dirname)
	defer os.Unsetenv("PELICAN_XROOTD_RUNLOCATION")
	config_dirname := t.TempDir()
	viper.Set("Origin.SelfTest", true)
	viper.Set("ConfigDir", config_dirname)
	viper.Set("Xrootd.RunLocation", dirname)
	viper.Set("Xrootd.Port", 8443)
	viper.Set("Server.Hostname", "origin.example.com")
	err := config.InitServer(ctx, config.OriginType)
	require.Nil(t, err)

	scitokensCfg := param.Xrootd_ScitokensConfig.GetString()
	err = config.MkdirAll(filepath.Dir(scitokensCfg), 0755, -1, -1)
	require.NoError(t, err)
	err = os.WriteFile(scitokensCfg, []byte(toMergeOutput), 0640)
	require.NoError(t, err)

	err = WriteOriginScitokensConfig([]string{"/foo/bar"})
	require.NoError(t, err)

	genCfg, err := os.ReadFile(filepath.Join(dirname, "scitokens-origin-generated.cfg"))
	require.NoError(t, err)

	assert.Equal(t, string(monitoringOutput), string(genCfg))
}
