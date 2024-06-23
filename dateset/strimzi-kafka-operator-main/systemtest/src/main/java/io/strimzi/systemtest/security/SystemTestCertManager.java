/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.systemtest.security;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import static io.strimzi.systemtest.security.SystemTestCertAndKeyBuilder.endEntityCertBuilder;
import static io.strimzi.systemtest.security.SystemTestCertAndKeyBuilder.intermediateCaCertBuilder;
import static io.strimzi.systemtest.security.SystemTestCertAndKeyBuilder.rootCaCertBuilder;
import static io.strimzi.systemtest.security.SystemTestCertAndKeyBuilder.strimziCaCertBuilder;
import static io.strimzi.test.k8s.KubeClusterResource.cmdKubeClient;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;

public class SystemTestCertManager {

    private static final String KAFKA_CERT_FILE_PATH = "/opt/kafka/broker-certs/";
    private static final String ZK_CERT_FILE_PATH = "/opt/kafka/zookeeper-node-certs/";
    private static final String CA_FILE_PATH = "/opt/kafka/cluster-ca-certs/ca.crt";
    static final String STRIMZI_ROOT_CA = "C=CZ, L=Prague, O=Strimzi, CN=StrimziRootCA";
    static final String STRIMZI_INTERMEDIATE_CA = "C=CZ, L=Prague, O=Strimzi, CN=StrimziIntermediateCA";
    static final String STRIMZI_END_SUBJECT = "C=CZ, L=Prague, O=Strimzi, CN=kafka.strimzi.io";

    private static List<String> generateBaseSSLCommand(String server, String caFilePath, String hostname) {
        return new ArrayList<>(asList("echo -n | openssl",
                "s_client",
                "-connect", server,
                "-showcerts",
                "-CAfile", caFilePath,
                "-verify_hostname", hostname
        ));
    }

    public static String generateOpenSslCommandByComponentUsingSvcHostname(String namespaceName, String podName, String hostname, String port, String component) {
        return generateOpenSslCommandByComponent(namespaceName, podName + "." + hostname + ":" + port,
                podName + "." + hostname + "." + namespaceName + ".svc.cluster.local", podName, component, true);
    }

    public static String generateOpenSslCommandByComponent(String namespaceName, String server, String hostname, String podName, String component) {
        return generateOpenSslCommandByComponent(namespaceName, server, hostname, podName, component, true);
    }

    public static String generateOpenSslCommandByComponent(String namespaceName, String server, String hostname, String podName, String component, boolean withCertAndKey) {
        String path = component.equals("kafka") ? KAFKA_CERT_FILE_PATH : ZK_CERT_FILE_PATH;
        List<String> cmd = generateBaseSSLCommand(server, CA_FILE_PATH, hostname);

        if (withCertAndKey) {
            cmd.add("-cert " + path + podName + ".crt");
            cmd.add("-key " + path + podName + ".key");
        }

        return cmdKubeClient(namespaceName).execInPod(podName, "/bin/bash", "-c", String.join(" ", cmd)).out();
    }

    public static List<String> getCertificateChain(String certificateName) {
        return new ArrayList<>(asList(
                "s:O = io.strimzi, CN = " + certificateName + "\n" +
                "   i:O = io.strimzi, CN = cluster-ca",
                "Server certificate\n" +
                "subject=O = io.strimzi, CN = " + certificateName + "\n\n" +
                "issuer=O = io.strimzi, CN = cluster-ca"
        ));
    }

    public static SystemTestCertAndKey generateRootCaCertAndKey() {
        return rootCaCertBuilder()
                .withIssuerDn(STRIMZI_ROOT_CA)
                .withSubjectDn(STRIMZI_ROOT_CA)
                .build();
    }

    public static SystemTestCertAndKey generateRootCaCertAndKey(final String rootCaDn, final ASN1Encodable[] sanDnsNames) {
        return rootCaCertBuilder()
            .withIssuerDn(rootCaDn)
            .withSubjectDn(rootCaDn)
            .withSanDnsNames(sanDnsNames)
            .build();
    }

    public static SystemTestCertAndKey generateIntermediateCaCertAndKey(SystemTestCertAndKey rootCert) {
        return intermediateCaCertBuilder(rootCert)
                .withSubjectDn(STRIMZI_INTERMEDIATE_CA)
                .build();
    }

    public static SystemTestCertAndKey generateStrimziCaCertAndKey(SystemTestCertAndKey rootCert, String subjectDn) {
        return strimziCaCertBuilder(rootCert)
                .withSubjectDn(subjectDn)
                .build();
    }

    public static SystemTestCertAndKey generateEndEntityCertAndKey(final SystemTestCertAndKey intermediateCert,
                                                                   final ASN1Encodable[] sansNames) {
        return endEntityCertBuilder(intermediateCert)
                .withSubjectDn(STRIMZI_END_SUBJECT)
                .withSanDnsNames(sansNames)
                .build();
    }

    public static SystemTestCertAndKey generateEndEntityCertAndKey(SystemTestCertAndKey intermediateCert) {
        return endEntityCertBuilder(intermediateCert)
                .withSubjectDn(STRIMZI_END_SUBJECT)
                .withSanDnsName("*.127.0.0.1.nip.io")
                .build();
    }

    public static CertAndKeyFiles exportToPemFiles(SystemTestCertAndKey... certs) {
        if (certs.length == 0) {
            throw new IllegalArgumentException("List of certificates should has at least one element");
        }
        try {
            File keyFile = exportPrivateKeyToPemFile(certs[0].getPrivateKey());
            File certFile = exportCertsToPemFile(certs);
            return new CertAndKeyFiles(certFile, keyFile);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static File convertPrivateKeyToPKCS8File(PrivateKey privatekey) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        byte[] encoded = privatekey.getEncoded();
        final PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(encoded);

        final ASN1Encodable asn1Encodable = privateKeyInfo.parsePrivateKey();
        final byte[] privateKeyPKCS8Formatted = asn1Encodable.toASN1Primitive().getEncoded(ASN1Encoding.DER);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyPKCS8Formatted);

        KeyFactory kf = KeyFactory.getInstance(SystemTestCertAndKeyBuilder.KEY_PAIR_ALGORITHM);
        PrivateKey privateKey = kf.generatePrivate(keySpec);
        return  exportPrivateKeyToPemFile(privateKey);
    }

    private static File exportPrivateKeyToPemFile(PrivateKey privateKey) throws IOException {
        File keyFile = Files.createTempFile("key-", ".key").toFile();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(keyFile, UTF_8))) {
            pemWriter.writeObject(privateKey);
            pemWriter.flush();
        }
        return keyFile;
    }

    private static File exportCertsToPemFile(SystemTestCertAndKey... certs) throws IOException {
        File certFile = Files.createTempFile("crt-", ".crt").toFile();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(certFile, UTF_8))) {
            for (SystemTestCertAndKey certAndKey : certs) {
                pemWriter.writeObject(certAndKey.getCertificate());
            }
            pemWriter.flush();
        }
        return certFile;
    }

    /**
     * This method exports Certificate Authority (CA) data to a temporary file for cases in which mentioned data is
     * necessary in form of file - for use in applications like OpenSSL. The primary purpose is to save CA files,
     * such as certificates and private keys (e.g., ca.key and ca.cert), into temporary files.
     * These files are essential when you need to provide CA data to other applications, such as OpenSSL,
     * for signing user Certificate Signing Requests (CSRs).
     *
     * @param caData The Certificate Authority data to be saved to the temporary file.
     * @param prefix The prefix for the temporary file's name.
     * @param suffix The suffix for the temporary file's name.
     * @return A File object representing the temporary file containing the CA data.
     * @throws RuntimeException If an IOException occurs while creating a file or writing into the temporary file
     * given the critical role these operations play in ensuring proper functionality.
     */
    public static File exportCaDataToFile(String caData, String prefix, String suffix) {
        try {
            File tempFile = Files.createTempFile(prefix + "-", suffix).toFile();

            try (FileWriter fileWriter = new FileWriter(tempFile, StandardCharsets.UTF_8)) {
                fileWriter.write(caData);
                fileWriter.flush();
            }

            return tempFile;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean containsAllDN(String principal1, String principal2) {
        try {
            return new LdapName(principal1).getRdns().containsAll(new LdapName(principal2).getRdns());
        } catch (InvalidNameException e) {
            e.printStackTrace();
        }
        return false;
    }
}
