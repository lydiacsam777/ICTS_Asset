using System.Data;
using System.Data.SqlClient;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Net;
using System.Net.Mail;
using Newtonsoft.Json;
using static System.Net.Mime.MediaTypeNames;

namespace ICTS_ASSETS.AppCode
{
    public class ICTSLibrary
    {
        public static String SqlConnectionString = "";
        public static String SecretKey = "";

        public class DAL : IDisposable
        {
            public DAL(IConfiguration configuration)
            {
                SqlConnectionString = configuration.GetConnectionString("SqlConnectionString");
                SecretKey = configuration.GetValue<String>("SecretKey");
            }

            public SqlConnection? ClientSqlCon { get; set; }
            void IDisposable.Dispose()
            {
                if (ClientSqlCon != null)
                    ClientSqlCon.Dispose();
            }

            public UserRoleClass? GetSessionInfo(HttpContext? httpContext)
            {
                UserRoleClass? userRoleClass = null;
                ISession Session = httpContext.Session;
                if (httpContext.Session.IsAvailable)
                {
                    if (String.IsNullOrEmpty(Session.GetString("UserId")))
                    {
                    }
                    else
                    {
                        userRoleClass = new UserRoleClass();
                        userRoleClass.UserId = Session.GetString("UserId");
                        userRoleClass.RoleId = Session.GetString("RoleId");
                    }
                }
                return userRoleClass;
            }
            public Boolean IsUserLoggedIn(HttpContext? httpContext)
            {
                ISession Session = httpContext.Session;
                if (httpContext.Session.Keys.Count() > 0)
                {
                    if (String.IsNullOrEmpty(Session.GetString("UserId")))
                    {
                        return false;
                    }
                    else
                    {
                        return true;
                    }
                }
                else
                {
                    try
                    {
                        String cookieKey = "_egl";
                        var CookieLogin = httpContext.Request.Cookies[cookieKey];
                        if (CookieLogin != null)
                        {
                            String? encCookieString = CookieLogin.ToString();
                            String? decryptedCookieQueryString = Decrypt(encCookieString);

                            String? UserId = HttpUtility.ParseQueryString(decryptedCookieQueryString).Get("userid");
                            String? RoleId = HttpUtility.ParseQueryString(decryptedCookieQueryString).Get("roleid");

                            httpContext.Session.SetString("UserId", UserId);
                            httpContext.Session.SetString("RoleId", RoleId);
                            return true;
                        }
                        else
                        {
                            return false;
                        }
                    }
                    catch { return false; }
                }
            }
            public Boolean IsPublicUserLoggedIn(HttpContext? httpContext)
            {
                ISession Session = httpContext.Session;
                if (httpContext.Session.Keys.Count() > 0)
                {
                    if (String.IsNullOrEmpty(Session.GetString("PublicUserId")))
                    {
                        return false;
                    }
                    else
                    {
                        return true;
                    }
                }
                else
                {
                    try
                    {
                        String cookieKey = "_pegl";
                        var CookieLogin = httpContext.Request.Cookies[cookieKey];
                        if (CookieLogin != null)
                        {
                            String? encCookieString = CookieLogin.ToString();
                            String? decryptedCookieQueryString = Decrypt(encCookieString);

                            String? PublicUserId = HttpUtility.ParseQueryString(decryptedCookieQueryString).Get("publicuserid");

                            httpContext.Session.SetString("PublicUserId", PublicUserId);
                            return true;
                        }
                        else
                        {
                            return false;
                        }
                    }
                    catch { return false; }
                }
            }
            public String CheckLoginPublic(String Username, String Password, HttpContext httpContext, bool keeplogin = true)
            {
                List<SqlParameter> sqlParams = new List<SqlParameter>();
                sqlParams.Add(new System.Data.SqlClient.SqlParameter("@Email", Username));
                sqlParams.Add(new System.Data.SqlClient.SqlParameter("@Password", Password));
                DataSet ds = SqlDataSetResult("USP_CheckWebUserLogin", sqlParams);

                if (ds.Tables[0].Rows.Count > 0)
                {
                    httpContext.Session.SetString("PublicUserId", Username);
                    if (keeplogin)
                    {
                        String cookieKey = "_pegl";
                        var CookieLogin = httpContext.Request.Cookies[cookieKey];
                        if (CookieLogin == null)
                        {
                            String cookieQueryString = "publicuserid=" + Username;
                            CookieOptions newCookieLogin = new CookieOptions();
                            newCookieLogin.Expires = DateTime.Now.AddYears(1);
                            String encryptedCookieQueryString = Encrypt(cookieQueryString);
                            httpContext.Response.Cookies.Append(cookieKey, encryptedCookieQueryString, newCookieLogin);
                        }
                    }
                    return "Active";
                }
                else
                {
                    return "NoUser";
                }
            }
            public String CheckLogin(String Username, String Password, HttpContext httpContext, bool keeplogin)
            {
                List<System.Data.SqlClient.SqlParameter> sqlParams = new List<System.Data.SqlClient.SqlParameter>();
                sqlParams.Add(new System.Data.SqlClient.SqlParameter("@Username", Username));
                //sqlParams.Add(new System.Data.SqlClient.SqlParameter("@Password", Encrypt(Password)));
                sqlParams.Add(new System.Data.SqlClient.SqlParameter("@Password", Password));
                sqlParams.Add(new System.Data.SqlClient.SqlParameter("@SecretKey", SecretKey));
                DataSet ds = SqlDataSetResult("USP_CheckLogin", sqlParams);
                UserMaster account = ConvertDataTableToClass<UserMaster>(ds.Tables[0]);
                if (account != null)
                {
                    if (account.USR_Status == "Active")
                    {
                        httpContext.Session.SetString("UserId", account.USR_DocNo.ToString());
                        httpContext.Session.SetString("RoleId", account.USR_RoleID.ToString());

                        if (keeplogin)
                        {
                            String cookieKey = "_egl";
                            var CookieLogin = httpContext.Request.Cookies[cookieKey];
                            if (CookieLogin == null)
                            {
                                String cookieQueryString = "userid=" + account.USR_DocNo + "&roleid=" + account.USR_RoleID;
                                CookieOptions newCookieLogin = new CookieOptions();
                                newCookieLogin.Expires = DateTime.Now.AddYears(1);
                                String encryptedCookieQueryString = Encrypt(cookieQueryString);
                                httpContext.Response.Cookies.Append(cookieKey, encryptedCookieQueryString, newCookieLogin);
                            }
                        }

                        return "Active";
                    }
                    else if (account.USR_Status == null)
                    {
                        return "NoUser";
                    }
                    else
                    {
                        return "InActive";
                    }
                }
                else
                {
                    return "NoUser";
                }

            }

            public PublicUserRoleClass? GetSessionInfopublic(HttpContext? httpContext)
            {
                PublicUserRoleClass? PublicUserRoleClass = null;
                ISession Session = httpContext.Session;
                if (httpContext.Session.IsAvailable)
                {
                    if (String.IsNullOrEmpty(Session.GetString("PublicUserId")))
                    {
                    }
                    else
                    {
                        PublicUserRoleClass = new PublicUserRoleClass();
                        PublicUserRoleClass.PublicUserId = Session.GetString("PublicUserId");

                    }
                }
                return PublicUserRoleClass;
            }
            public String CheckLoginPublic_NoPswd(String Username, HttpContext httpContext, bool keeplogin = true)
            {
                httpContext.Session.SetString("PublicUserId", Username);
                if (keeplogin)
                {
                    String cookieKey = "_pegl";
                    var CookieLogin = httpContext.Request.Cookies[cookieKey];
                    if (CookieLogin == null)
                    {
                        String cookieQueryString = "publicuserid=" + Username;
                        CookieOptions newCookieLogin = new CookieOptions();
                        newCookieLogin.Expires = DateTime.Now.AddYears(1);
                        String encryptedCookieQueryString = Encrypt(cookieQueryString);
                        httpContext.Response.Cookies.Append(cookieKey, encryptedCookieQueryString, newCookieLogin);
                    }
                }
                return "Active";
            }
            public String EncryptText(String text)
            {
                return Encrypt(text);
            }
            public String DecryptText(String text)
            {
                return Decrypt(text);
            }
            public DataSet SaveRecord(IFormCollection form, string webRootPath, EntryFormClass ModelClass, String USR_DocNo, int imgMaxWidth = 1000, int imgMaxHeight = 1000)
            {
                bool InsertRecord = false;
                String? docNo_ColumnValue = form[ModelClass.DocNo_Column];
                String? doctype = ModelClass.HeaderTablePrefix;
                var headerFormlist = new Dictionary<string, string>();
                var detailFormlist = new Dictionary<string, string>();
                var detaillist = new Dictionary<string, string>();
                String headerTablePrefix = ModelClass.HeaderTablePrefix + "_";

                List<Dictionary<string, object>> galleryList = new List<Dictionary<string, object>>();
                Dictionary<string, object> galleryRow;

                int i = 0;
                foreach (string key in form.Keys)
                {
                    if (key.StartsWith(headerTablePrefix))
                    {
                        headerFormlist.Add(key, form[key]);
                    }
                }

                if (form.Files.Count > 0)
                {
                    //contains files..
                    foreach (var file in form.Files)
                    {
                        String fileUrl = "";
                        String fileID = GetUniqueID();
                        String filePath = "";

                        String extension = System.IO.Path.GetExtension(file.FileName).ToLower();
                        if (extension.Equals(".jpg") || extension.Equals(".jpeg")
                            || extension.Equals(".png") || extension.Equals(".gif") || extension.Equals(".tiff"))
                        {
                            filePath = "/uploads/images/";
                            fileUrl = filePath + fileID + ".jpg";
                        }
                        else
                        {
                            filePath = "/uploads/docs/";
                            fileUrl = filePath + fileID + extension;
                        }
                        SaveFile(postedfile: file, fileUrl: fileUrl, filePath: webRootPath + filePath.Replace("/", @"\"), webRootPath, imgWidth: imgMaxWidth, imgHeight: imgMaxHeight);
                        if (file.Name == "Gallery" && doctype == "NSEV")
                        {
                            galleryRow = new Dictionary<string, object>();
                            galleryRow.Add(file.Name, fileUrl);
                            galleryList.Add(galleryRow);
                        }
                        else
                        {
                            headerFormlist.Add(file.Name, fileUrl);
                        }

                    }
                }



                String? tableName = ""; String sqlQuery = "";
                String? formName = "";

                List<SqlParameter> sqlPrm = new List<SqlParameter>();
                sqlPrm.Add(new SqlParameter("@DocType", ModelClass.doctype));
                sqlPrm.Add(new SqlParameter("@USR_DocNo", USR_DocNo));
                DataSet ds = SqlDataSetResult("USP_STG_GetSaveSettings", sqlPrm);
                tableName = ds.Tables[0].Rows[0]["TableName"].ToString();
                formName = ds.Tables[0].Rows[0]["FormName"].ToString();
                UserPermission userPermission = ConvertDataTableToClass<UserPermission>(ds.Tables[1]);

                List<SqlParameter> sqlParameters = new List<SqlParameter>();
                String headerColumnNameString = "";
                String paramColumnNameString = "";
                String updateParamColumnString = "";
                foreach (string key in headerFormlist.Keys)
                {
                    headerColumnNameString += key + ",";
                    paramColumnNameString += "@" + key + ",";
                    updateParamColumnString += key + "=@" + key + ",";
                    if (String.IsNullOrEmpty(docNo_ColumnValue) && key == ModelClass.DocNo_Column)
                    {
                        InsertRecord = true;
                        docNo_ColumnValue = ds.Tables[0].Rows[0]["DocNo"].ToString();
                        sqlParameters.Add(new SqlParameter("@" + key, docNo_ColumnValue));
                    }
                    else
                    {
                        sqlParameters.Add(new SqlParameter("@" + key, headerFormlist[key]));
                    }
                }
                headerColumnNameString = headerColumnNameString.TrimEnd(',');
                headerColumnNameString = headerColumnNameString + "," + ModelClass.HeaderTablePrefix + "_Status";
                headerColumnNameString = headerColumnNameString + "," + ModelClass.HeaderTablePrefix + "_Created_By";
                headerColumnNameString = headerColumnNameString + "," + ModelClass.HeaderTablePrefix + "_Created_TS";

                paramColumnNameString = paramColumnNameString.TrimEnd(',');
                paramColumnNameString = paramColumnNameString + ",@" + ModelClass.HeaderTablePrefix + "_Status";
                paramColumnNameString = paramColumnNameString + ",@" + ModelClass.HeaderTablePrefix + "_Created_By";
                paramColumnNameString = paramColumnNameString + ",@" + ModelClass.HeaderTablePrefix + "_Created_TS";

                updateParamColumnString = updateParamColumnString.TrimEnd(',');


                if (InsertRecord)
                {
                    if (userPermission.DM_Add == true)
                    {
                        sqlQuery = "INSERT INTO " + tableName;
                        sqlQuery += "(" + headerColumnNameString + ")";
                        sqlQuery += " VALUES(" + paramColumnNameString + ")";
                        sqlQuery += " SELECT 'New " + formName + " Added' as Message";
                        sqlParameters.Add(new SqlParameter("@" + ModelClass.HeaderTablePrefix + "_Status", "Active"));
                        sqlParameters.Add(new SqlParameter("@" + ModelClass.HeaderTablePrefix + "_Created_By", USR_DocNo));
                        sqlParameters.Add(new SqlParameter("@" + ModelClass.HeaderTablePrefix + "_Created_TS", DateTimeNow().ToString("yyyy/MM/dd hh:mm:ss")));
                    }
                    else
                    {
                        sqlQuery = "SELECT 'No Permission.!' as Message";
                        sqlParameters = new List<SqlParameter>();
                    }
                }
                else
                {
                    if (userPermission.DM_Edit == true)
                    {
                        sqlQuery = "UPDATE " + tableName + " SET ";
                        sqlQuery += updateParamColumnString;
                        sqlQuery += " WHERE " + ModelClass.DocNo_Column + "=@" + ModelClass.HeaderTablePrefix + "_DocNo";
                        sqlQuery += " SELECT '" + formName + " Updated' as Message";
                    }
                    else
                    {
                        sqlQuery = "SELECT 'No Permission.!' as Message";
                        sqlParameters = new List<SqlParameter>();
                    }
                }
                if (doctype == "NSEV" && galleryList.Count != 0)
                {
                    string galleryimagesjson = JsonConvert.SerializeObject(galleryList);
                    List<SqlParameter> sqlPrm1 = new List<SqlParameter>();
                    sqlPrm1.Add(new SqlParameter("@galleryimagesJSON", galleryimagesjson));
                    sqlPrm1.Add(new SqlParameter("@DocNo", docNo_ColumnValue));
                    sqlPrm1.Add(new SqlParameter("@DocType", "NSEVG"));
                    DataSet ds1 = SqlDataSetResult("USP_Admin_NewsAndEvents_Gallery", sqlPrm1);
                }
                DataSet dataSet = SqlDataSetResult(sqlQuery, sqlParameters, false);
                return dataSet;
            }
            public DataSet DeleteRecord(String doctype, String docno, String userid)
            {
                if (doctype == "PP")
                {
                    List<SqlParameter> sqlParameters = new List<SqlParameter>();
                    String sqlQuery1 = "";
                    sqlQuery1 = "SELECT 'Deleted' as Message";
                    sqlParameters = new List<SqlParameter>();
                    List<SqlParameter> sqlPrm1 = new List<SqlParameter>();
                    sqlPrm1.Add(new SqlParameter("@DocType", doctype));
                    sqlPrm1.Add(new SqlParameter("@DocNo", docno));
                    DataSet ds1 = SqlDataSetResult("USP_Delete_PremiProperty", sqlPrm1);
                    DataSet dataSet = SqlDataSetResult(sqlQuery1, sqlParameters, false);

                    return dataSet;
                }
                else if (doctype == "RP")
                {
                    List<SqlParameter> sqlParameters = new List<SqlParameter>();
                    String sqlQuery2 = "";
                    sqlQuery2 = "SELECT 'Deleted' as Message";
                    sqlParameters = new List<SqlParameter>();
                    List<SqlParameter> sqlPrm1 = new List<SqlParameter>();
                    sqlPrm1.Add(new SqlParameter("@DocType", doctype));
                    sqlPrm1.Add(new SqlParameter("@DocNo", docno));
                    DataSet ds1 = SqlDataSetResult("USP_Delete_RecommProperty", sqlPrm1);
                    DataSet dataSet = SqlDataSetResult(sqlQuery2, sqlParameters, false);
                    return dataSet;
                }
                else
                {
                    List<SqlParameter> sqlPrm = new List<SqlParameter>();
                    sqlPrm.Add(new SqlParameter("@DocType", doctype));
                    sqlPrm.Add(new SqlParameter("@USR_DocNo", userid));
                    DataSet ds = SqlDataSetResult("USP_STG_GetSaveSettings", sqlPrm);
                    String tableName = ds.Tables[0].Rows[0]["TableName"].ToString();
                    String TablePrefix = ds.Tables[0].Rows[0]["TablePrefix"].ToString();
                    String FormName = ds.Tables[0].Rows[0]["FormName"].ToString();
                    UserPermission userPermission = ConvertDataTableToClass<UserPermission>(ds.Tables[1]);

                    List<SqlParameter> sqlParameters = new List<SqlParameter>();
                    String sqlQuery = "";
                    sqlParameters.Add(new SqlParameter(TablePrefix + "_DocNo", docno));
                    if (userPermission.DM_Delete == true)
                    {
                        //sqlQuery = "DELETE FROM " + tableName;
                        sqlQuery = "UPDATE " + tableName + " SET ";
                        sqlQuery += TablePrefix + "_Status= 'Deleted'";
                        sqlQuery += " WHERE " + TablePrefix + "_DocNo=@" + TablePrefix + "_DocNo";
                        sqlQuery += " SELECT '" + FormName + " deleted' as Message";

                    }
                    else
                    {
                        sqlQuery = "SELECT 'No Permission.!' as Message";
                        sqlParameters = new List<SqlParameter>();
                    }
                    DataSet dataSet = SqlDataSetResult(sqlQuery, sqlParameters, false);
                    //DataSet dataSet = SqlDataSetResult("USP_STG_Default_Delete", sqlParameters);

                    return dataSet;
                }
            }
            public DataSet SaveRecordOLD(IFormCollection form, string webRootPath, EntryFormClass ModelClass, int imgMaxWidth = 1000, int imgMaxHeight = 1000)
            {
                String? docNo_ColumnValue = form[ModelClass.DocNo_Column];
                var headerFormlist = new Dictionary<string, string>();
                var detailFormlist = new Dictionary<string, string>();
                String headerTablePrefix = ModelClass.HeaderTablePrefix + "_";

                foreach (string key in form.Keys)
                {
                    if (key.StartsWith(headerTablePrefix))
                    {
                        String formValue = form[key];
                        formValue = formValue.TrimStart('\r').TrimStart('\n');
                        formValue = formValue.TrimEnd('\r').TrimEnd('\n');
                        headerFormlist.Add(key, formValue);
                    }
                }

                if (form.Files.Count > 0)
                {
                    //contains files..
                    foreach (var file in form.Files)
                    {
                        String fileUrl = "";
                        String fileID = GetUniqueID();
                        String filePath = "";

                        String extension = System.IO.Path.GetExtension(file.FileName).ToLower();
                        if (extension.Equals(".jpg") || extension.Equals(".jpeg")
                            || extension.Equals(".png") || extension.Equals(".gif") || extension.Equals(".tiff"))
                        {
                            filePath = "/uploads/images/";
                            fileUrl = filePath + fileID + ".jpg";
                        }
                        else
                        {
                            filePath = "/uploads/docs/";
                            fileUrl = filePath + fileID + extension;
                        }
                        SaveFile(postedfile: file, fileUrl: fileUrl, filePath: webRootPath + filePath.Replace("/", @"\"), webRootPath, imgWidth: imgMaxWidth, imgHeight: imgMaxHeight);
                        headerFormlist.Add(file.Name, fileUrl);
                    }
                }

                String headerColumnNameString = "";
                foreach (string key in headerFormlist.Keys)
                {
                    headerColumnNameString += key + ",";
                }
                headerColumnNameString = headerColumnNameString.TrimEnd(',');

                string headerJsonData = JsonConvert.SerializeObject(headerFormlist);


                List<SqlParameter> sqlParameters = new List<SqlParameter>();
                sqlParameters.Add(new SqlParameter("@HeaderColumnNames", headerColumnNameString));
                sqlParameters.Add(new SqlParameter("@HeaderColumnValues", headerJsonData));
                sqlParameters.Add(new SqlParameter("@DocType", ModelClass.doctype));
                sqlParameters.Add(new SqlParameter("@DocNo_Column", ModelClass.DocNo_Column));
                sqlParameters.Add(new SqlParameter("@DocNo_Value", docNo_ColumnValue));

                DataSet dataSet = SqlDataSetResult("USP_STG_Default_Header_Save", sqlParameters);
                return dataSet;
            }
            public void SaveFile(IFormFile postedfile, string fileUrl, string filePath, string webRootPath, int imgWidth = 1000, int imgHeight = 1000)
            {
                //if (fileUrl.EndsWith(".jpg"))
                //{
                //    //var image = Image.FromStream(postedfile.OpenReadStream());
                //    //var resized = new Bitmap(image, new Size(1000, 1000));
                //    //using var imageStream = new MemoryStream();
                //    //resized.Save(imageStream, ImageFormat.Jpeg);
                //}
                //else
                //{
                String fullfilePath = webRootPath + fileUrl;
                if (Directory.Exists(filePath))
                {
                }
                else
                {
                    Directory.CreateDirectory(filePath);
                }
                using (FileStream stream = new FileStream(fullfilePath, FileMode.Create))
                {
                    postedfile.CopyTo(stream);
                }
            }
            public void DeleteFile(string file, string type, IWebHostEnvironment _webHostEnvironment)
            {
                string fileDirectory = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/uploads/" + type + "/");
                string webRootPath = _webHostEnvironment.WebRootPath;
                var fileName = "";
                fileName = file;
                var fullPath = webRootPath + file;

                if (System.IO.File.Exists(fullPath))
                {
                    System.IO.File.Delete(fullPath);
                }
            }

            public DataSet SqlDataSetResult(String storedProcedureName, List<SqlParameter> sqlParams, Boolean isStoredProcedure = true)
            {
                DataSet ds = new DataSet();
                using (ClientSqlCon = new SqlConnection(SqlConnectionString))
                {
                    SqlTransaction transaction;
                    ClientSqlCon.Open();
                    transaction = ClientSqlCon.BeginTransaction();
                    try
                    {
                        SqlCommand clientSqlCmd = new SqlCommand(storedProcedureName, ClientSqlCon, transaction)
                        {
                            CommandType = (isStoredProcedure) ? CommandType.StoredProcedure : CommandType.Text,
                            CommandTimeout = 0
                        };

                        if (sqlParams.Count > 0)
                        {
                            clientSqlCmd.Parameters.AddRange(sqlParams.ToArray());
                        }

                        SqlDataAdapter da = new SqlDataAdapter(clientSqlCmd);
                        da.Fill(ds);
                        transaction.Commit();
                        ClientSqlCon.Close();
                    }
                    catch (Exception ex)
                    {
                        String? USR_DocNo = "";
                        try
                        {
                            SqlParameter? logID = sqlParams.Where(t => t.ParameterName == "LGN_DocNo").FirstOrDefault();
                            USR_DocNo = (logID != null) ? logID.Value.ToString() : "";
                        }
                        catch { }
                        //SaveERRORLogs(USR_DocNo, storedProcedureName, ex.Message, (ex.InnerException == null) ? "" : ex.InnerException.ToString());

                        transaction.Rollback();
                        ClientSqlCon.Close();
                    }
                }
                return ds;
            }
            private void SaveERRORLogs(String? USR_DocNo, String ErrorPage, String ErrorDetails, String? InnerException)
            {
                List<SqlParameter> sqlParameters = new List<SqlParameter>();
                sqlParameters.Add(new SqlParameter("@USR_DocNo", USR_DocNo));
                sqlParameters.Add(new SqlParameter("@ErrorPage", ErrorPage));
                sqlParameters.Add(new SqlParameter("@ErrorDetails", ErrorDetails));
                sqlParameters.Add(new SqlParameter("@InnerException", InnerException));

                DataSet dataSet = SqlDataSetResult("USP_SaveErrorLogs", sqlParameters);
            }

            public List<T> ConvertDataTableToListClass<T>(DataTable dt)
            {
                List<T> data = new List<T>();
                try
                {
                    data = dt.AsEnumerable().Select(row => GetItem<T>(row)).ToList();
                }
                catch (Exception ex) { data = new List<T>(); }
                return data;
            }
            public T ConvertDataTableToClass<T>(DataTable dt) where T : new()
            {
                T item = new T();
                try
                {
                    DataRow row = dt.Rows[0];
                    // set the item
                    SetItemFromRow(item, row);
                }
                catch { }
                return item;
            }
            public string GetUniqueID()
            {
                string ID = "";
                ID = "" + DateTime.Now.Year + "" + DateTime.Now.Month + "" + DateTime.Now.Day + "" + DateTime.Now.Hour + DateTime.Now.Minute + "" + DateTime.Now.Second + "" + DateTime.Now.Millisecond;
                return ID;
            }
            public DateTime DateTimeNow()
            {
                DateTime todaysDate = DateTime.Now;
                //String DateTimeString = todaysDate.ToString("dd-MMM-yyy HH:mm:ss");
                //DateTime ResultDateTime = Convert.ToDateTime(DateTimeString);
                return todaysDate;
            }
            #region Private Methods
            private string Encrypt(string encryptString)
            {
                String MyEncryptionKey = SecretKey;
                byte[] clearBytes = Encoding.Unicode.GetBytes(encryptString);
                using (Aes encryptor = Aes.Create())
                {
                    Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(MyEncryptionKey, new byte[] {
                    0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76
                });
                    encryptor.Key = pdb.GetBytes(32);
                    encryptor.IV = pdb.GetBytes(16);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(clearBytes, 0, clearBytes.Length);
                            cs.Close();
                        }
                        encryptString = Convert.ToBase64String(ms.ToArray());
                    }
                }
                return encryptString;
            }
            private string Decrypt(string cipherText)
            {
                String MyEncryptionKey = SecretKey;
                cipherText = cipherText.Replace(" ", "+");
                byte[] cipherBytes = Convert.FromBase64String(cipherText);
                using (Aes encryptor = Aes.Create())
                {
                    Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(MyEncryptionKey, new byte[] {
                    0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76
                });
                    encryptor.Key = pdb.GetBytes(32);
                    encryptor.IV = pdb.GetBytes(16);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(cipherBytes, 0, cipherBytes.Length);
                            cs.Close();
                        }
                        cipherText = Encoding.Unicode.GetString(ms.ToArray());
                    }
                }
                return cipherText;
            }
            private void SetItemFromRow<T>(T item, DataRow row) where T : new()
            {
                foreach (DataColumn c in row.Table.Columns)
                {
                    PropertyInfo? p = item.GetType().GetProperty(c.ColumnName);
                    if (p != null && row[c] != DBNull.Value)
                    {
                        p.SetValue(item, row[c], null);
                    }
                }
            }
            private T GetItem<T>(DataRow dr)
            {
                Type temp = typeof(T);
                T obj = Activator.CreateInstance<T>();
                foreach (DataColumn column in dr.Table.Columns)
                {
                    PropertyInfo? pro = temp.GetProperties().Where(t => t.Name == column.ColumnName).FirstOrDefault();
                    if (pro != null)
                    {
                        var cellValue = dr[column.ColumnName];
                        cellValue = (cellValue == DBNull.Value) ? "" : cellValue;
                        pro.SetValue(obj, cellValue, null);
                    }
                }
                return obj;
            }
            #endregion Private Methods
            public String DataTableToJSON(Object table)
            {
                string JSONString = string.Empty;
                JSONString = JsonConvert.SerializeObject(table);
                return JSONString;
            }

        }
          




        public class DocumentSettings
        {
            public String? DM_DocType { get; set; }
            public String? DM_DocNo { get; set; }
            public String? DM_Doc_DocType { get; set; }
            public String? DM_SP_Name { get; set; }
            public String? DM_FormName { get; set; }
            public String? DM_URL { get; set; }
            public String? DM_EntryForm { get; set; }
            public String? DM_EntryFormPartial { get; set; }
            public String? DM_GridPartial { get; set; }
            public String? DM_Entry_SP { get; set; }
            public String? DM_Insert_SP { get; set; }
            public String? DM_Delete_SP { get; set; }
            public String? DM_Status { get; set; }
            public String? DM_Table { get; set; }
            public String? DM_TablePrefix { get; set; }
            public String? DM_EntryFormSide_Flag { get; set; }
            public String? DM_Grid_Col_md { get; set; }
            public String? DM_Form_Col_md { get; set; }
            public String? DM_DocIcon { get; set; }

            public DataTable? dtGridData { get; set; }
            public DataTable? dtData { get; set; }

            public Boolean DM_Add { get; set; }
            public Boolean DM_Edit { get; set; }
            public Boolean DM_Delete { get; set; }
            public Boolean DM_View { get; set; }
            public Boolean DM_Permission { get; set; }
            public Boolean OnlyView { get; set; }
        }
        private class UserPermission
        {
            public Boolean DM_Add { get; set; }
            public Boolean DM_Edit { get; set; }
            public Boolean DM_Delete { get; set; }
        }
        private class UserMaster
        {
            public string? USR_DocNo { get; set; }
            public string? USR_Username { get; set; }
            public string? USR_Email { get; set; }
            public string? USR_Status { get; set; }
            public string USR_RoleID { get; set; }
        }
        public class EntryFormClass
        {
            public string? doctype { get; set; }
            public string DocNo_Column { get; set; }
            public string DocNo_Value { get; set; }
            public string? FormName { get; set; }
            public string? EntryForm { get; set; }
            public string? HeaderTablePrefix { get; set; }
            public string? PostFromFormName { get; set; }
            public string? EntrySP { get; set; }
        }
        public class UserRoleClass
        {
            public String? UserId { get; set; }
            public String? RoleId { get; set; }
        }

        public class PublicUserRoleClass
        {
            public String? PublicUserId { get; set; }

        }
    }
   
}
