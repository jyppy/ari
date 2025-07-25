As per the RFC A. Gable RFC 9773: ACME Renewal Information (ARI) Extension, one need to supply the certificate AKI (X509v3 Authority Key Identifier: 21:CD:36:59:5D:66:DF:0C:06:FD:21:39:22:C5:4C:04:B7:58:20:B8 ) and Serial number (ie: serial=13ABB82181F3AC0F3C63640DDC3BF638B2B47382) to the ACME CA responder to check if certificate is flagged to be renewed

The computed value concatenates in Base64 encoded the binary (DER) AKI.SER

ie: Ic02WV1m3wwG/SE5IsVMBLdYILg.E6u4IYHzrA88Y2QN3Dv2OLK0c4I

