//go:build windows

package filescan

import (
	"crypto/sha1"
	"encoding/hex"
	"unsafe"

	"golang.org/x/sys/windows"
)

const cmsgSignerInfoParam = 6

func verifySignature(path string) (bool, error) {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}

	data := &windows.WinTrustData{
		Size:             uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:         windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_WHOLECHAIN,
		UnionChoice:      windows.WTD_CHOICE_FILE,
		StateAction:      windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&windows.WinTrustFileInfo{
			Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
			FilePath: path16,
		}),
	}

	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)

	if verifyErr == nil {
		return true, nil
	}
	return false, verifyErr
}

func signerCertificate(path string) (*windows.CertContext, bool) {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, false
	}

	var (
		encodingType uint32
		contentType  uint32
		formatType   uint32
		store        windows.Handle
		msg          windows.Handle
	)

	err = windows.CryptQueryObject(
		windows.CERT_QUERY_OBJECT_FILE,
		unsafe.Pointer(path16),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED|windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		windows.CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		&encodingType,
		&contentType,
		&formatType,
		&store,
		&msg,
		nil,
	)
	if err != nil {
		return nil, false
	}
	defer func() {
		if store != 0 {
			_ = windows.CertCloseStore(store, 0)
		}
		if msg != 0 {
			cryptMsgClose(msg)
		}
	}()

	var size uint32
	if err := cryptMsgGetParam(msg, cmsgSignerInfoParam, 0, nil, &size); err != nil || size == 0 {
		return nil, true
	}
	buf := make([]byte, size)
	if err := cryptMsgGetParam(msg, cmsgSignerInfoParam, 0, unsafe.Pointer(&buf[0]), &size); err != nil {
		return nil, true
	}

	signer := (*cmsgSignerInfo)(unsafe.Pointer(&buf[0]))
	certInfo := windows.CertInfo{
		SerialNumber: signer.SerialNumber,
		Issuer:       signer.Issuer,
	}
	cert, err := windows.CertFindCertificateInStore(
		store,
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		0,
		windows.CERT_FIND_SUBJECT_CERT,
		unsafe.Pointer(&certInfo),
		nil,
	)
	if err != nil {
		return nil, true
	}
	dup := windows.CertDuplicateCertificateContext(cert)
	_ = windows.CertFreeCertificateContext(cert)
	return dup, true
}

func certSubject(cert *windows.CertContext) string {
	if cert == nil {
		return ""
	}
	chars := windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, nil, 0)
	if chars <= 1 {
		return ""
	}
	buf := make([]uint16, chars)
	windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &buf[0], chars)
	return windows.UTF16ToString(buf)
}

func certThumbprint(cert *windows.CertContext) string {
	if cert == nil || cert.EncodedCert == nil || cert.Length == 0 {
		return ""
	}
	data := unsafe.Slice(cert.EncodedCert, int(cert.Length))
	sum := sha1.Sum(data)
	return stringsUpperHex(sum[:])
}

func stringsUpperHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	hexStr := hex.EncodeToString(data)
	buf := []byte(hexStr)
	for i, b := range buf {
		if b >= 'a' && b <= 'f' {
			buf[i] = b - ('a' - 'A')
		}
	}
	return string(buf)
}
