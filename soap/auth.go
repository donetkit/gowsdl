package soap

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// HttpBaseAuthSnapshotImage 通过http base 认证方式获取设备快照,返回图片二进制
func HttpBaseAuthSnapshotImage(url, username, passwd string) ([]byte, error) {
	httpClient := &http.Client{}
	/* 生成需要访问的http.Request信息 */
	if request, err := http.NewRequest("GET", url, nil); err == nil {
		/*
			鉴权方法
				在http请求头中添加
					Authorization  值为 "Basic " + Base64("name:passwd")
				例如:
					admin:123 qw ea sd ZXC Base64 后 YWRtaW46MTIzcXdlYXNkWlhD
					则 Authorization 的值为 "Base64 YWRtaW46MTIzcXdlYXNkWlhD"
		*/
		request.Header.Add("Authorization", "Base64 "+base64.StdEncoding.EncodeToString([]byte(username+":"+passwd)))
		if response, err := httpClient.Do(request); err == nil {
			defer response.Body.Close()
			if imageBytes, err := io.ReadAll(response.Body); err == nil {
				return imageBytes, nil
			} else {
				return nil, err
			}
		}
	} else {
		return nil, err
	}
	return nil, errors.New("unknown error")
}

// HttpDigestAuthGetSnapshotImage 通过http digest 认证方式获取设备快照,返回图片二进制
func HttpDigestAuthGetSnapshotImage(url, username, password string) ([]byte, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		return nil, fmt.Errorf("recieved status code '%d' auth skipped", resp.StatusCode)
	}
	digestParts := digestParts(resp)
	digestParts["uri"] = url
	digestParts["method"] = "GET"
	digestParts["username"] = username
	digestParts["password"] = password
	req, _ = http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", getDigestAuthorization(digestParts))
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return body, nil
	}
	return nil, fmt.Errorf("response status code '%v'", resp.StatusCode)
}

// HttpDigestAuthGetSnapshotImageClient 通过http digest 认证方式获取设备快照,返回图片二进制
func HttpDigestAuthGetSnapshotImageClient(url, username, password string, client *http.Client) ([]byte, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		return nil, fmt.Errorf("recieved status code '%d' auth skipped", resp.StatusCode)
	}
	digestParts := digestParts(resp)
	digestParts["uri"] = url
	digestParts["method"] = "GET"
	digestParts["username"] = username
	digestParts["password"] = password
	req, _ = http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", getDigestAuthorization(digestParts))
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return body, nil
	}
	return nil, fmt.Errorf("response status code '%v'", resp.StatusCode)
}

func digestParts(resp *http.Response) map[string]string {
	result := map[string]string{}
	if len(resp.Header["Www-Authenticate"]) > 0 {
		wantedHeaders := []string{"nonce", "realm", "qop"}
		responseHeaders := strings.Split(resp.Header["Www-Authenticate"][0], ",")
		for _, r := range responseHeaders {
			for _, w := range wantedHeaders {
				if strings.Contains(r, w) {
					result[w] = strings.Split(r, `"`)[1]
				}
			}
		}
	}
	return result
}

func getMD5(text string) string {
	hashMd5 := md5.New()
	hashMd5.Write([]byte(text))
	return hex.EncodeToString(hashMd5.Sum(nil))
}

func getNonce() string {
	b := make([]byte, 8)
	io.ReadFull(rand.Reader, b)
	return fmt.Sprintf("%x", b)[:16]
}

func getDigestAuthorization(digestParts map[string]string) string {
	d := digestParts
	ha1 := getMD5(d["username"] + ":" + d["realm"] + ":" + d["password"])
	ha2 := getMD5(d["method"] + ":" + d["uri"])
	nonceCount := 1
	nonceStr := strings.ToUpper(getNonce()) + strings.ToUpper(getNonce())
	response := getMD5(fmt.Sprintf("%s:%s:%08d:%s:%s:%s", ha1, d["nonce"], nonceCount, nonceStr, d["qop"], ha2))
	//authorization := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", cnonce="%s", nc="%v", qop="%s", response="%s", algorithm="md5"`,	d["username"], d["realm"], d["nonce"], d["uri"], nonceStr, nonceCount, d["qop"], response)

	// Authorization: Digest username="xdadmin",realm="IP Camera(L4161)",qop="auth",algorithm=MD5,uri="/onvif/device_service",nonce="616539313a62333031653032393a16b5900f4975069c2fdc1e250894542f",nc=00000001,cnonce="22C5FA768BBD378CD1276BCAC37EE430",response="eb7c7628639bc91b4de6909dfe508b74"

	authorization := fmt.Sprintf(`Digest username="%s",realm="%s",qop="%s",algorithm=MD5,uri="%s",nonce="%s",nc=%08d,cnonce="%s",response="%s"`,
		d["username"], d["realm"], d["qop"], d["uri"], d["nonce"], nonceCount, nonceStr, response)

	return authorization
}
