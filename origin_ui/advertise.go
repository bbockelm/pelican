package origin_ui

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/pelicanplatform/pelican/director"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func PeriodicAdvertiseOrigin() error {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		err := AdvertiseOrigin()
		if err != nil {
			log.Warningln("Origin advertise failed:", err)
		}
		for {
			<-ticker.C
			err := AdvertiseOrigin()
			if err != nil {
				log.Warningln("Origin advertise failed:", err)
			}
		}
	}()

	return nil
}

func AdvertiseOrigin() error {
	name := viper.GetString("Sitename")
	if name == "" {
		return errors.New("Origin name isn't set")
	}
	namespacePrefix := viper.GetString("NamespacePrefix")
	if namespacePrefix == "" {
		return errors.New("No namespace is exported by origin")
	}

	token, err := director.CreateAdvertiseToken(namespacePrefix)
	if err != nil {
		return errors.Wrap(err, "Failed to create token to advertise to the director")
	}

	originUrl := fmt.Sprintf("https://%v:%v", viper.GetString("Hostname"), viper.GetInt("WebPort"))

	issuerUrlStr, err := director.GetIssuerURL(namespacePrefix)
	if err != nil {
		return errors.Wrap(err, "Failed to generate issuer URL")
	}
	issuerUrl, err := url.Parse(issuerUrlStr)
	if err != nil {
		return errors.Wrapf(err, "Failed to parse issuer URL %v", issuerUrlStr)
	}

	ad := director.OriginAdvertise{
		Name: name,
		URL:  originUrl,
		Namespaces: []director.NamespaceAd{
			director.NamespaceAd{
				RequireToken: true,
				Path: namespacePrefix,
				Issuer: *issuerUrl,
				MaxScopeDepth: viper.GetUint("Issuer.MaxScopeDepth"),
				Strategy: director.OAuthStrategy,
				BasePath: namespacePrefix,
			},
		},
	}

	body, err := json.Marshal(ad)
	if err != nil {
		return errors.Wrap(err, "Failed to generate JSON description of origin")
	}

	directorUrlStr := viper.GetString("DirectorURL")
	if directorUrlStr == "" {
		return errors.New("Director endpoint URL is not known")
	}
	directorUrl, err := url.Parse(directorUrlStr)
	if err != nil {
		return errors.Wrap(err, "Failed to parse DirectorURL")
	}
	directorUrl.Path = "/api/v1.0/director/registerOrigin"

	log.Debugln("Advertising origin at URL", directorUrl.String())
	req, err := http.NewRequest("POST", directorUrl.String(), bytes.NewBuffer(body))
	if err != nil {
		return errors.Wrap(err, "Failed to create POST request for director registration")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer " + token)

	client := http.Client{}
	if viper.GetBool("TLSSkipVerify") {
		log.Debugln("Disabling TLS verification for origin advertising")
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = http.Client{Transport: tr}
	} else {
		log.Debugln("Will advertise to director over TLS")
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failed to start request for director registration")
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return fmt.Errorf("Error response %v from director registration: %v", resp.StatusCode, resp.Status)
	}

	return nil
}
