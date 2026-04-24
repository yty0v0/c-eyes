//go:build windows

package filescan

import "golang.org/x/sys/windows"

func signatureInfo(path string) *FileSignatureInfo {
	cert, signed := signerCertificate(path)
	if !signed {
		return nil
	}

	info := &FileSignatureInfo{
		IsSigned: boolPtr(true),
	}

	if cert != nil {
		defer windows.CertFreeCertificateContext(cert)
		if subject := certSubject(cert); subject != "" {
			info.SignerSubject = &subject
		}
		if thumb := certThumbprint(cert); thumb != "" {
			info.CertificateThumbprint = &thumb
		}
	}

	if valid, err := verifySignature(path); err == nil {
		info.SignatureValid = boolPtr(valid)
	} else {
		info.SignatureValid = boolPtr(false)
	}

	return info
}
