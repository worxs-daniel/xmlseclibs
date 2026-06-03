--TEST--
RSA-OAEP encryption/decryption and OAEP hash detection (XML Encryption 1.1)
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecEnc;

/* Helper: locate and load the private key for decryption */
function loadPrivateKey($objKey) {
    $objKey->loadKey(dirname(__FILE__) . '/privkey.pem', TRUE);
}

/* Helper: decrypt an encrypted XML document and return the decrypted XML */
function decryptDocument($encryptedXml) {
    $decDoc = new DOMDocument();
    $decDoc->loadXML($encryptedXml);

    $objenc = new XMLSecEnc();
    $encData = $objenc->locateEncryptedData($decDoc);
    $objenc->setNode($encData);
    $objenc->type = $encData->getAttribute("Type");
    $objKey = $objenc->locateKey();
    if (!$objKey) {
        throw new Exception("Unable to locate algorithm for encrypted data");
    }

    $objKeyInfo = $objenc->locateKeyInfo($objKey);
    if ($objKeyInfo && $objKeyInfo->isEncrypted) {
        loadPrivateKey($objKeyInfo);
        $key = $objKeyInfo->encryptedCtx->decryptKey($objKeyInfo);
        $objKey->loadKey($key);
    } else {
        loadPrivateKey($objKey);
    }

    $decrypted = $objenc->decryptNode($objKey, true);
    return $decDoc->saveXML();
}

/* Helper: get the digest from a key using reflection (cryptParams is private) */
function getKeyDigest($key) {
    $ref = new ReflectionProperty(XMLSecurityKey::class, 'cryptParams');
    $ref->setAccessible(true);
    $params = $ref->getValue($key);
    return $params['digest'] ?? null;
}

/* Load original document for comparison */
$originalDoc = new DOMDocument();
$originalDoc->load(dirname(__FILE__) . '/basic-doc.xml');
$originalXml = $originalDoc->saveXML();

/* Test 1: Round-trip RSA-OAEP-MGF1P (SHA-1 default) encrypt/decrypt */
echo "Test RSA-OAEP-MGF1P round-trip: ";

$dom1 = new DOMDocument();
$dom1->load(dirname(__FILE__) . '/basic-doc.xml');

$objKey1 = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
$objKey1->generateSessionKey();

$siteKey1 = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type'=>'public'));
$siteKey1->loadKey(dirname(__FILE__) . '/mycert.pem', TRUE, TRUE);

$enc1 = new XMLSecEnc();
$enc1->setNode($dom1->documentElement);
$enc1->encryptKey($siteKey1, $objKey1);
$enc1->type = XMLSecEnc::Element;
$enc1->encryptNode($objKey1);

try {
    $decrypted1 = decryptDocument($dom1->saveXML());
    if ($decrypted1 === $originalXml) {
        echo "Passed\n";
    } else {
        echo "Failed (decrypted content mismatch)\n";
    }
} catch (Exception $e) {
    echo "Failed (" . $e->getMessage() . ")\n";
}

/* Test 2: RSA-OAEP (XML Enc 1.1, SHA-256 default) round-trip */
echo "Test RSA-OAEP round-trip: ";

$dom2 = new DOMDocument();
$dom2->load(dirname(__FILE__) . '/basic-doc.xml');

$objKey2 = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
$objKey2->generateSessionKey();

$siteKey2 = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP, array('type'=>'public'));
$siteKey2->loadKey(dirname(__FILE__) . '/mycert.pem', TRUE, TRUE);

$enc2 = new XMLSecEnc();
$enc2->setNode($dom2->documentElement);
$enc2->encryptKey($siteKey2, $objKey2);
$enc2->type = XMLSecEnc::Element;
$enc2->encryptNode($objKey2);

try {
    $decrypted2 = decryptDocument($dom2->saveXML());
    if ($decrypted2 === $originalXml) {
        echo "Passed\n";
    } else {
        echo "Failed (decrypted content mismatch)\n";
    }
} catch (Exception $e) {
    echo "Failed (" . $e->getMessage() . ")\n";
}

/* Test 3: OAEP hash detection - MGF sha256 override
 * Create an EncryptedKey with xenc11:MGF element and verify digest is detected.
 */
echo "Test OAEP hash detection (MGF sha256): ";

$mgfTestXml = '<?xml version="1.0"?>
<xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/>
    <xenc11:MGF>
        <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/>
    </xenc11:MGF>
    <xenc:CipherData>
        <xenc:CipherValue>AkYzMjE=</xenc:CipherValue>
    </xenc:CipherData>
</xenc:EncryptedKey>';

$mgfDoc = new DOMDocument();
$mgfDoc->loadXML($mgfTestXml);
$mgfElement = $mgfDoc->documentElement;

try {
    $detectedKey = XMLSecurityKey::fromEncryptedKeyElement($mgfElement);
    $digest = getKeyDigest($detectedKey);
    if ($digest === 'sha256') {
        echo "Passed\n";
    } else {
        echo "Failed (got: " . ($digest ?? 'null') . ")\n";
    }
} catch (Exception $e) {
    echo "Failed (exception: " . $e->getMessage() . ")\n";
}

/* Test 4: OAEP hash detection via DigestMethod fallback */
echo "Test OAEP hash detection (DigestMethod sha512): ";

$digestTestXml = '<?xml version="1.0"?>
<xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/>
    <xenc:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
    <xenc:CipherData>
        <xenc:CipherValue>AkYzMjE=</xenc:CipherValue>
    </xenc:CipherData>
</xenc:EncryptedKey>';

$digestDoc = new DOMDocument();
$digestDoc->loadXML($digestTestXml);
$digestElement = $digestDoc->documentElement;

try {
    $detectedKey2 = XMLSecurityKey::fromEncryptedKeyElement($digestElement);
    $digest2 = getKeyDigest($detectedKey2);
    if ($digest2 === 'sha512') {
        echo "Passed\n";
    } else {
        echo "Failed (got: " . ($digest2 ?? 'null') . ")\n";
    }
} catch (Exception $e) {
    echo "Failed (exception: " . $e->getMessage() . ")\n";
}

/* Test 5: OAEP hash detection - MGF takes precedence over DigestMethod */
echo "Test OAEP hash detection (MGF precedence): ";

$precedenceTestXml = '<?xml version="1.0"?>
<xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/>
    <xenc11:MGF>
        <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha384"/>
    </xenc11:MGF>
    <xenc:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
    <xenc:CipherData>
        <xenc:CipherValue>AkYzMjE=</xenc:CipherValue>
    </xenc:CipherData>
</xenc:EncryptedKey>';

$precedenceDoc = new DOMDocument();
$precedenceDoc->loadXML($precedenceTestXml);
$precedenceElement = $precedenceDoc->documentElement;

try {
    $detectedKey3 = XMLSecurityKey::fromEncryptedKeyElement($precedenceElement);
    $digest3 = getKeyDigest($detectedKey3);
    if ($digest3 === 'sha384') {
        echo "Passed\n";
    } else {
        echo "Failed (got: " . ($digest3 ?? 'null') . ")\n";
    }
} catch (Exception $e) {
    echo "Failed (exception: " . $e->getMessage() . ")\n";
}

/* Test 6: OAEP with no MGF/DigestMethod keeps default (sha256) */
echo "Test OAEP hash detection (no override keeps default): ";

$noOverrideTestXml = '<?xml version="1.0"?>
<xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/>
    <xenc:CipherData>
        <xenc:CipherValue>AkYzMjE=</xenc:CipherValue>
    </xenc:CipherData>
</xenc:EncryptedKey>';

$noOverrideDoc = new DOMDocument();
$noOverrideDoc->loadXML($noOverrideTestXml);
$noOverrideElement = $noOverrideDoc->documentElement;

try {
    $detectedKey4 = XMLSecurityKey::fromEncryptedKeyElement($noOverrideElement);
    $digest4 = getKeyDigest($detectedKey4);
    if ($digest4 === 'sha256') {
        echo "Passed\n";
    } else {
        echo "Failed (got: " . ($digest4 ?? 'null') . ")\n";
    }
} catch (Exception $e) {
    echo "Failed (exception: " . $e->getMessage() . ")\n";
}

?>
--EXPECTF--
Test RSA-OAEP-MGF1P round-trip: Passed
Test RSA-OAEP round-trip: Passed
Test OAEP hash detection (MGF sha256): Passed
Test OAEP hash detection (DigestMethod sha512): Passed
Test OAEP hash detection (MGF precedence): Passed
Test OAEP hash detection (no override keeps default): Passed
