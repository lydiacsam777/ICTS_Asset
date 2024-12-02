using Microsoft.AspNetCore.Mvc;
using ICTS_ASSETS;
using System.Data;
using System.Data.SqlClient;
using System.Web;
using System.IO;
using System.Xml.Serialization;
using System.Net;
using System.Text.Json;
using ICTS_ASSETS.AppCode;

namespace ICTS_ASSETS.Controllers
{
    public class AdminController : Controller
    {
        #region Declarations
        public static String SqlConnectionString = "";
        public String SecretKey = ""; // Key Used for encrypted/decryption (passwords/cookies/etc..)
        public string WebRootPath = ""; //Website absolute path
        #endregion Declarations

        #region Constructor
        private readonly IWebHostEnvironment _webHostEnvironment;
        private readonly IConfiguration _configuration;

        public object JsonRequestBehavior { get; private set; }

        public AdminController(IWebHostEnvironment webHostEnvironment, IConfiguration configuration)
        {
            _webHostEnvironment = webHostEnvironment; _configuration = configuration;
            SqlConnectionString = configuration.GetConnectionString("SqlConnectionString");
            SecretKey = configuration.GetValue<String>("SecretKey");
            WebRootPath = _webHostEnvironment.WebRootPath;
        }
        #endregion Constructor       

        #region Views/Pages
        public IActionResult Index()
        {
            //HttpContext.Session.SetString("UserId", "admin");
            //HttpContext.Session.SetString("RoleId", "1");
            //using (CommonLibrary.DataAccess db = new CommonLibrary.DataAccess())
            //{
            //    String passEncrypted = db.EncryptText("1234");
            //}
            return View();
        }
        public IActionResult Login()
        {
            return View();
        }
        [HttpPost]
        public IActionResult Login(IFormCollection form)
        {

            using (ICTSLibrary.DAL db = new ICTSLibrary.DAL(_configuration))
            {
                String Username = form["Username"];
                String Password = form["Password"];
                String kpString = form["keeplogin"];
                bool keeplogin = (kpString == null) ? false : true;
                String result = db.CheckLogin(Username, Password, HttpContext, keeplogin);
                if (result.Equals("Active"))
                {
                    TempData["Message"] = "Login Success";
                    return Redirect("/admin/dashboard");
                }
                else if (result.Equals("InActive"))
                {
                    TempData["Message"] = "User login is InActive.!";
                }
                else
                {
                    TempData["Message"] = "Invalid User credentials.!";
                }
                return View();
            }
        }

        public IActionResult Dashboard()
        {
            //String viewUrl = "/admin/Asset";
            return View();
        }

        public IActionResult Asset()
        {
            return View();
        }

        public IActionResult AddAsset()
        {

            return View();
        }

        [Route("admin/EntryForm")]
        public IActionResult EntryForm(string doctype, String docno = "")
        {
            return View();
        }
        [HttpPost]
        [Route("admin/EntryForm")]
        public IActionResult EntryForm(IFormCollection form, ICTSLibrary.EntryFormClass model)
        {
            using (ICTSLibrary.DAL db = new ICTSLibrary.DAL(_configuration))
            {
                String? USR_DocNo = HttpContext.Session.GetString("UserId");
                DataSet ds = db.SaveRecord(form: form, webRootPath: WebRootPath, ModelClass: model, USR_DocNo: USR_DocNo);

                TempData["Message"] = ds.Tables[0].Rows[0]["Message"]; //set message from dataset..
                                                                       //ViewBag.Message = "New Property Type added";
                var doctype = model.doctype;                                                     //String viewUrl = "/admin/" + model.PostFromFormName + "?doctype=" + model.doctype + (String.IsNullOrEmpty(Request.Query["docno"]) ? "" : "&docno=" + Request.Query["docno"]);
                String viewUrl = "";                                                 //String viewUrl = "/admin/" + model.PostFromFormName + "?doctype=" + model.doctype + (String.IsNullOrEmpty(Request.Query["docno"]) ? "" : "&docno=" + Request.Query["docno"]);
                if (model.PostFromFormName == "AboutEntry")
                {
                    viewUrl = "/admin/AboutEntry?doctype=ABT";
                }
                else if (model.doctype == "CNS" || model.doctype == "EML" || model.doctype == "OFRBAN")
                {
                    viewUrl = "/admin/EntryForm?doctype=" + model.doctype + "&docno=1000";
                }

                else
                {
                    viewUrl = "/admin/MasterList?doctype=" + model.doctype;
                }



                return Redirect(viewUrl);

            }
        }
        public JsonResult deleterecord(String doctype, string docno)
        {
            using (ICTSLibrary.DAL db = new ICTSLibrary.DAL(_configuration))
            {
                String? userid = HttpContext.Session.GetString("UserId");
                DataSet ds = db.DeleteRecord(doctype, docno, userid);
                //TempData["Message"] = ds.Tables[0].Rows[0]["Message"];
                String Message = ds.Tables[0].Rows[0]["Message"] + "";

                return Json(Message);
            }
        }

        public IActionResult UserEntryForm(string doctype, String docno = "")
        {
            return View();
        }
        [HttpPost]
        [Route("admin/UserEntryForm")]
        public IActionResult UserEntryForm(IFormCollection form, ICTSLibrary.EntryFormClass model)
        {
            string Message = "Something went wrong";
            using (ICTSLibrary.DAL db = new ICTSLibrary.DAL(_configuration))
            {
                string HeaderData = form["HeaderArray"];
                string DataData = form["DataArray"];
                string loginID = form["LoginID"];
                string DocType = form["doctype"];
                string DocNo = form["docno"];
                string password = db.EncryptText(form["USR_Password"]);

                List<SqlParameter> sqlParameters = new List<SqlParameter>();
                sqlParameters.Add(new SqlParameter("@USR_DocNo", loginID));
                sqlParameters.Add(new SqlParameter("@DocType", DocType));
                sqlParameters.Add(new SqlParameter("@DocNo", DocNo));
                sqlParameters.Add(new SqlParameter("@HeaderJson", HeaderData));
                sqlParameters.Add(new SqlParameter("@DataJson", DataData));
                sqlParameters.Add(new SqlParameter("@Password", password));
                DataSet dataSet = db.SqlDataSetResult("USP_Admin_USR_Save", sqlParameters);
                Message = dataSet.Tables[0].Rows[0]["Status"].ToString();
            }
            TempData["Message"] = Message;
            //TempData["Message"] = "New Property Type added"; //set message from dataset..
            //String viewUrl = "/admin/" + model.PostFromFormName + "?doctype=" + model.doctype + (String.IsNullOrEmpty(Request.Query["docno"]) ? "" : "&docno=" + Request.Query["docno"]);
            String viewUrl = "/admin/" + model.PostFromFormName + "?doctype=" + model.doctype;
            return Redirect(viewUrl);
        }
        public IActionResult AboutEntry(String doctype)
        {
            return View();
        }


        public JsonResult DeleteGroupRecommProperty(string doctype, string grpdocno)
        {

            using (ICTSLibrary.DAL db = new ICTSLibrary.DAL(_configuration))
            {
                List<SqlParameter> sqlParameters = new List<SqlParameter>();
                sqlParameters.Add(new SqlParameter("@doctype", doctype));
                sqlParameters.Add(new SqlParameter("@grpdocno", grpdocno));
                DataSet dataSet = db.SqlDataSetResult("USP_Delete_RecommProperty", sqlParameters);
                String Message = (dataSet.Tables[0].Rows[0]["STATUS"].ToString());
                return Json(Message);

            }

        }



        public IActionResult MasterList(String doctype)
        {
            return View();
        }
        public JsonResult LoadGridData(String doctype)
        {
            using (ICTSLibrary.DAL db = new ICTSLibrary.DAL(_configuration))
            {
                var draw = Request.Form["draw"].FirstOrDefault();
                // Skiping number of Rows count  
                var start = Request.Form["start"].FirstOrDefault();
                // Paging Length 10,20  
                var length = Request.Form["length"].FirstOrDefault();
                // Sort Column Name  
                var sortColumn = Request.Form["columns[" + Request.Form["order[0][column]"].FirstOrDefault() + "][name]"].FirstOrDefault();
                // Sort Column Direction ( asc ,desc)  
                var sortColumnDirection = Request.Form["order[0][dir]"].FirstOrDefault();
                // Search Value from (Search box)  
                var searchValue = Request.Form["search[value]"].FirstOrDefault();

                //Paging Size (10,20,50,100)  
                int pageSize = length != null ? Convert.ToInt32(length) : 0;
                int skip = start != null ? Convert.ToInt32(start) : 0;
                int recordsTotal = 0;

                DataSet ds = db.SqlDataSetResult("select * from dbo.tbl_PropertyMaster_Test", new List<System.Data.SqlClient.SqlParameter>(), isStoredProcedure: false);
                DataTable dt = ds.Tables[0];
                var gridData = dt.AsEnumerable().ToList();
                // Getting all data  
                //var gridData = (from tempcustomer in _context.CustomerTB
                //                select tempcustomer);

                //Sorting  
                if (!(string.IsNullOrEmpty(sortColumn) && string.IsNullOrEmpty(sortColumnDirection)))
                {
                    //gridData = gridData.OrderBy(sortColumn + " " + sortColumnDirection);
                }
                //Search  
                if (!string.IsNullOrEmpty(searchValue))
                {
                    //gridData = gridData.Where(m => m.Name == searchValue);
                }

                //total number of rows count   
                recordsTotal = gridData.Count();
                //Paging   
                var data = gridData.Skip(skip).Take(pageSize).ToList();

                return Json(new { draw = draw, recordsFiltered = recordsTotal, recordsTotal = recordsTotal, data = data });
            }
        }

        public IActionResult logout()
        {
            HttpContext.Session.Clear();


            foreach (var cookie in Request.Cookies.Keys)
            {
                Response.Cookies.Delete(cookie);
            }
            return Redirect("/admin/login");
        }


        public ActionResult getentrypartial(string partialName, ICTS_ASSETS.AppCode.ICTSLibrary.EntryFormClass model)
        {
            return PartialView("~" + partialName, model);
        }      

        #endregion Views/Pages


        public IActionResult DataGrid(String doctype)
        {
            return View();
        }



        public JsonResult StatusDisableEnablePopUp(string DocNo, string DocType, string StatusUpdate)
        {
            using (ICTSLibrary.DAL db = new ICTSLibrary.DAL(_configuration))
            {
                List<SqlParameter> sqlParams = new List<SqlParameter>();
                sqlParams.Add(new SqlParameter("@DocNo", DocNo));
                sqlParams.Add(new SqlParameter("@DocType", DocType));
                sqlParams.Add(new SqlParameter("@StatusUpdate", StatusUpdate));
                DataSet dsResult = db.SqlDataSetResult("USP_DisbaleEnableStatus_Popup", sqlParams);
                String Message = (dsResult.Tables[0].Rows[0]["Message"].ToString());
                return Json(Message);

            }
        }

      





    }
}
