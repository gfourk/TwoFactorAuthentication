package crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import utils.*;
import crypto.*;
import java.io.Serializable;


/**
 * 
 * @author vvasil
 *
 */
public class HY457Certificate implements Serializable{
	
	
	private long serialNo;
	private String owner;
	private String issuer;
	private Date not_before;
	private Date not_after;
	private PublicKey publicKey;
	private byte[] signature;
	
	/******************************************************************************
	 * the fields and creates the signature
	 * @param serialNo
	 * @param owner
	 * @param issuer
	 * @param privateKey
	 * @param publicKey
	 * @throws Exception 
	 */
	public HY457Certificate ( String owner, String issuer, PrivateKey privateKey, PublicKey publicKey) throws Exception{
		// set all the fields
		this.serialNo = System.currentTimeMillis();
		this.owner = owner;
		this.issuer = issuer;
		this.publicKey = publicKey;
		this.not_before = new Date(System.currentTimeMillis() - 50000);
		this.not_after = new Date(System.currentTimeMillis() - 365*24*3600*1000);
		
		// finally sign the certificate
		byte all[] = this.merge_fields();
		this.signature = crypt.getSignature(all, privateKey);
	}
	
	/************************************************************************/
	/* getter functions														*/
	/************************************************************************/
	public long getSerialNo(){
		return this.serialNo;
	}
	public String getOwner(){
		return this.owner;
	}
	public String getIssuer(){
		return this.issuer;
	}
	public Date getsNotBeforeDate(){
		return this.not_before;
	}
	public Date getNotAfterDate(){
		return this.not_after;
	}
	public PublicKey getPublicKey(){
		return this.publicKey;
	}
	public byte[] getSignature(){
		return this.signature;
	}
	
	/******************************************************************************
	 * Checks the signature via the public key and returns true or false accordingly
	 * @param key
	 * @return
	 * @throws Exception 
	 */
	public boolean check(PublicKey key) throws Exception{
		return crypt.verifySignature(this.merge_fields(), key, this.signature);
	}
	
	/****************************************************************************
	 * merges all the fields apart from the signature into a byte array
	 * @return a byte array
	 */
	private byte[] merge_fields(){
		byte[] ret = (""+this.serialNo).getBytes();
		ret = utils.concat(ret, this.issuer.getBytes());
		ret = utils.concat(ret, this.owner.getBytes());
		ret = utils.concat(ret, (this.not_before.getTime()+"").getBytes());
		ret = utils.concat(ret, (this.not_after.getTime()+"").getBytes());
		ret = utils.concat(ret, this.publicKey.getEncoded());
		return ret;
	}
	
	
	
	
	
	/*
	public class X509V1CreateExample
	{
	   public static X509Certificate generateV1Certificate(KeyPair pair)
	      throws InvalidKeyException, NoSuchProviderException, SignatureException
	   {
	      // generate the certificate
	      

	      X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();

	      certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
	      certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
	      certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
	      certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
	      certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
	      certGen.setPublicKey(pair.getPublic());
	      certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

	      return certGen.generateX509Certificate(pair.getPrivate(), "BC");
	   }

	 */
	

}
