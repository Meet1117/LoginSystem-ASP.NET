If you know how to install Nuget Package, How to Add Connection String and Database Dependency Inject then skip Step 1 to Step 3 and Move to Step 4.


Step 1 : Intall 3 NueGet Packages

1. Microsoft.EntityFrameworkCore
2. Microsoft.EntityFrameworkCore.SqlServer
3.  Microsoft.EntityFrameworkCore.Tools






Step 2: Add Connection String 

Code: 

"ConnectionStrings": {
	"DefaultConnection": "Server=LAPTOP-L6QNGMK1\\SQLEXPRESS06;Database=LoginSystem_db_CRUD;Trusted_Connection=True;MultipleActiveResultSets=True;TrustServerCertificate=True"
},







Step 3: Add Database Dependecy Inject

Code: 

// Add after builder.Services.AddControllersWithViews();
IConfiguration configuration = new ConfigurationBuilder()
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json")
    .Build();

builder.Services.AddDbContext<DB>(options =>
    options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

Note: Put this code after the Authentication code (step 4 code)







Step 4: Add Authentication Dependencies in the Program.cs

Code: 

// Authentication Starts From Here
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(
    option =>
    {
        option.ExpireTimeSpan = TimeSpan.FromMinutes(60 * 1);
        option.LoginPath = "/Account/Login";
        option.AccessDeniedPath = "/Account/Login";
    });

builder.Services.AddSession(option =>
{
    option.IdleTimeout = TimeSpan.FromMinutes(5);
    option.Cookie.HttpOnly = true;
    option.Cookie.IsEssential = true;
});
// Authentication Ends Here

Note: Put this code after "builder.Services.AddControllersWithViews();" This line







Step 5: Create Main Model which handles the Whole Data

In My Case I have Model named Users.cs

Define Properties


Code: 

[Key] // Primary Key

public int Id { get; set; }

public string UserName { get; set; }

public string Email { get; set; }

public long? Mobile { get; set; }

public string Password { get; set;} 

public bool IsActive { get; set; }

public int LoginAttempt { get; set; } = 0;



Step 5.1: Create SignUpViewModel.cs

This ViewModel helps us for Validations of the SignUp Page

Code:

public int Id { get; set; }

//Username Validation
[Required(ErrorMessage = "Please enter username")]
[Remote(action: "UserNameIsExist", controller: "Account")]
public string UserName { get; set; }

//Email Validation
[Required(ErrorMessage = "Please enter email")]
[RegularExpression(@"^[\w-]+(\.[\w-]+)*@([\w-]+\.)+[a-zA-Z]{2,7}$")]
public string Email { get; set; }

//Mobile Number Validation
[Required(ErrorMessage = "Please enter Mobile Number")]
[Display(Name = "Mobile Number")]
[RegularExpression("^([0-9]{10})$", ErrorMessage = "Invalid Mobile Number.")]
public long? Mobile { get; set; }

//Password Validation
[Required(ErrorMessage = "Please enter Password")]
[RegularExpression("^((?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])|(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[^a-zA-Z0-9])|(?=.*?[A-Z])(?=.*?[0-9])(?=.*?[^a-zA-Z0-9])|(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^a-zA-Z0-9])).{8,}$", ErrorMessage = "Passwords must be at least 8 characters and contain at 3 of 4 of the following: upper case (A-Z), lower case (a-z), number (0-9) and special character (e.g. !@#$%^&*)")]
public string Password { get; set; }

//Confirm Password Validation
[Required(ErrorMessage = "Please enter Confirm Password")]
[Compare("Password", ErrorMessage = "The passwords do not match.")]
[Display(Name = "Confirm Password")]

//IsActive Validation
public string ConfirmPassword { get; set; }
[Display(Name = "Active")]
public bool IsActive { get; set; }




Step 5.2 Create LoginViewModel.cs handels Login

Code: 

public string Username { get; set; }

public string Password { get; set; }

[Display(Name = "Remember Me")]
public bool IsRemember { get; set; }



Step 6: Create Controller 

In my case I have created Controller named AccountController.cs

Code:

public class AccountController : Controller
{
	private readonly DB Context;
	
	public AccountController(DB Context)
	{
		this.context = context;
	}

	//SignUp Action 

	public IActionResult SignUp()
	{
    		return View();
	}

	[HttpPost]

	public IActionResult SignUp(SignUpViewModel model)
	{
		if(ModelState.IsValid)
		{
			var data = new User()
			{
				UserName = model.Username,
				Email = model.Email,
				Password = model.Password,
				Mobile = model.Mobile,
				IsActive = model.IsActive,
			}

			context.Users.Add(data);
			context.SaveChanges();
			TempData["successMessage"] = "You are eligible to login, please type your login credential";
			return RedirectToAction("Login");
		}
		else
		{
			TempData["error"] = "Empty form Can't be submitted!";
		}
	}


	//Login Action
	public IActionResult Login()
	{
		return View();
	}

	[HttpPost]

	public IActionResult Login(LoginSignUpViewModel model)
	{
		if (ModelState.IsValid)
    		{
        		var data = context.Users.Where(e => e.UserName == model.Username).SingleOrDefault();
        		if(data != null)
        		{
            			bool isValid = (data.UserName == model.Username && DecryptPassword(data.Password) == model.Password);
            			if (isValid)
            			{
                			var identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, model.Username) },
                    			CookieAuthenticationDefaults.AuthenticationScheme);
                			var principle = new ClaimsPrincipal(identity);
                			HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principle);
                			HttpContext.Session.SetString("Username", model.Username);
                			return RedirectToAction("Index", "Home");
            			}
            			else
            			{
                			IActionResult update(Users user)
                			{
                    				user.UserName = user.UserName;
                    				user.Email = user.Email;
                    				user.Mobile = user.Mobile;
                    				user.IsActive = user.IsActive;
                    				user.LoginAttempt = user.LoginAttempt;
                    				context.Users.Update(user);

						context.SaveChanges();
        	            			return View(user);
                			}
		        	        TempData["errorPassword"] = "Invalid Password";
                			return View(model);
            			}
        		}
        		else
        		{
            			TempData["errorUsername"] = "username not found!";
        		}
    		}
    		else
    		{
        		return View(model);
    		}
    		return View(model);
	}

	//Logout 
	public IActionResult LogOut()
	{
   		HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
	    	var stroedCookies = Request.Cookies.Keys;

		foreach(var cookies in stroedCookies)
    		{
        		Response.Cookies.Delete(cookies);
    		}
	
		return RedirectToAction("Login", "Account");
	}


	//Find If Username Already Exists or Not

	[AcceptVerbs("Post", "Get")]
	public IActionResult UserNameIsExist(string userName)
	{
    		var data = context.Users.Where(x => x.UserName == userName).SingleOrDefault();

		if (data != null)
    		{
        		return Json($"Username {userName} is already taken.");
    		}
    		else
    		{
        		return Json(true);
    		}
		return View();
	}

//Encrypt Passrword
public static string EncryptPassword(string password)
{
    if (string.IsNullOrEmpty(password))
    {
        return null;
    }
    else
    {
        byte[] storePasseword = ASCIIEncoding.ASCII.GetBytes(password);
        string encryptedPassword = Convert.ToBase64String(storePasseword);
        return encryptedPassword;
    }
}

//Decrypt Password
public static string DecryptPassword(string password)
{
    if (string.IsNullOrEmpty(password))
    {
        return null;
    }
    else
    {
        byte[] storePasseword = Convert.FromBase64String(password);
        string decryptedPassword = ASCIIEncoding.ASCII.GetString(storePasseword);
        return decryptedPassword;
    }
}


}

Step 7: Create AdminPanel Controller

AdminPanel.cs

Code:

private readonly DB mydb;

public AdminPanelController(DB mydb)
{
    this.mydb = mydb;
}

[Authorize]
public IActionResult GetData()
{
    IEnumerable<Users> xData = mydb.Users; 
    return View(xData);
}


Step 8: Create another Layout.cshtml

Go to -> Views/Shared/Layout.cshtml

copy whole Layout.cshtml and paste it in the same folder 

Now you have another Layout-copy.cshtml file

Change it with this code

Code: 

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>@ViewData["Title"] - WebAuthentication_UsingSessing</title>
    <link rel="stylesheet" href="~/lib/bootstrap/dist/css/bootstrap.min.css" />
    <link rel="stylesheet" href="~/css/site.css" asp-append-version="true" />
    <link rel="stylesheet" href="~/WebAuthentication_UsingSessing.styles.css" asp-append-version="true" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" integrity="sha512-SnH5WK+bZxgPHs44uWIX+LLJAJ9/2PkPKZ5QiAj6Ta86w+fsb2TkcmfRyVX3pBnMFcV7oQPJkl9QevSCWr3W6A==" crossorigin="anonymous" referrerpolicy="no-referrer"   />
</head>
<body>
   
    <div class="container">
        <main role="main" class="pb-3">
            @RenderBody()
        </main>
    </div>

    <script src="~/lib/jquery/dist/jquery.min.js"></script>
    <script src="~/lib/bootstrap/dist/js/bootstrap.bundle.min.js"></script>
    <script src="~/js/site.js" asp-append-version="true"></script>
    @await RenderSectionAsync("Scripts", required: false)
</body>
</html>


Step 9: Create Views for Login, SignUp, AdminPanel(GetData)

How to Create View? 

Go to Controller rightclick on the Action Method *In this Case SignUp

Right Click on SignUp -> Go to Add View -> Razor View -> Select Layout-copy.cshtml in Use a Layout Page (there is a option in the very last in the Add Razor View) -> Click in Add

Path : ~/Views/Shared/_Layout.cshtml






Step 9.1 SignUp View


@model WebAuthentication_UsingSessing.Models.SignUpUserViewModel

@{
	ViewData["Title"] = "SignUp";
	Layout = "~/Views/Shared/_Layout_Login.cshtml";
}

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<link href="~/css/login-signup.css" rel="stylesheet" />

<div class="container">
    <div class="row justify-content-center">
        <div class="col-lg-7 col-md-9">
            <div class="form-container">
                <div class="header">
                    <h1>Create Your Account</h1>
                    <p>Join our community and get started today</p>
                </div>

                <!-- Social Login Options -->
                <div class="social-login">
                    <a href="#" class="social-btn google">
                        <i class="fab fa-google"></i>
                    </a>
                    <a href="#" class="social-btn facebook">
                        <i class="fab fa-facebook-f"></i>
                    </a>
                    <a href="#" class="social-btn twitter">
                        <i class="fab fa-twitter"></i>
                    </a>
                </div>

                <div class="divider">or register with email</div>

                <!-- Validation Summary -->
                <div class="alert alert-danger d-none">
                    Please fix the errors below
                </div>

                <div asp-validation-summary="ModelOnly"></div>
                <form method="post" asp-action="SignUp">
                    <!-- Username -->
                    <div class="mb-4">
                        <label class="form-label">Username</label>
                        <div class="input-group">
                            <input asp-for="UserName" type="text" class="form-control" placeholder="Enter your username">
                            <span class="icon"><i class="fas fa-user"></i></span>
                        </div>
                        <span class="text-danger" asp-validation-for="UserName"></span>
                    </div>

                    <!-- Email and Mobile -->
                    <div class="row">
                        <div class="col-md-6 mb-4">
                            <label class="form-label">Email Address</label>
                            <div class="input-group">
                                <input asp-for="Email" type="email" class="form-control" placeholder="name@example.com">
                                <span class="icon"><i class="fas fa-envelope"></i></span>
                            </div>
                            <span class="text-danger" asp-validation-for="Email"></span>
                        </div>

                        <div class="col-md-6 mb-4">
                            <label class="form-label">Mobile Number</label>
                            <div class="input-group">
                                <input asp-for="Mobile" type="tel" class="form-control" placeholder="+91 6351243855" >
                                <span class="icon"><i class="fas fa-phone"></i></span>
                            </div>
                            <span class="text-danger" asp-validation-for="Mobile"></span>
                        </div>
                    </div>

                    <!-- Password and Confirm Password -->
                    <div class="row">
                        <div class="col-md-6 mb-4">
                            <label class="form-label">Password</label>
                            <div class="input-group">
                                <input asp-for="Password" type="password" class="form-control" placeholder="Create a password">
                                <span class="icon password-toggle"><i class="fas fa-eye"></i></span>
                            </div>
                            <div class="form-text">Use 8+ characters with a mix of letters & numbers</div>
                            <span class="text-danger" asp-validation-for="Password"></span>
                        </div>

                        <div class="col-md-6 mb-4">
                            <label class="form-label">Confirm Password</label>
                            <div class="input-group">
                                <input asp-for="ConfirmPassword" type="password" class="form-control" placeholder="Confirm your password">
                                <span class="icon password-toggle"><i class="fas fa-eye"></i></span>
                            </div>
                            <span class="text-danger" asp-validation-for="ConfirmPassword"></span>
                        </div>
                    </div>

                    <!-- Active Status -->
                    <div class="checkbox-container">
                        <input type="checkbox" checked="checked" asp-for="IsActive">
                        <label>Activate my account immediately</label>
                    </div>

                    <!-- Submit Button -->
                    <div class="d-grid">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-user-plus me-2"></i>Create Account
                        </button>
                    </div>
                </form>

                <!-- Login Link -->
                <div class="login-link">
                    Already have an account? <a asp-action="Login">Sign In</a>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    // Password toggle functionality
    document.querySelectorAll('.password-toggle').forEach(function(toggle) {
        toggle.addEventListener('click', function() {
            const input = this.closest('.input-group').querySelector('input');
            const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
            input.setAttribute('type', type);

            // Toggle eye icon
            this.querySelector('i').classList.toggle('fa-eye');
            this.querySelector('i').classList.toggle('fa-eye-slash');
        });
    });
</script>

<script src="~/lib/jquery/dist/jquery.min.js"></script>
<script src="~/lib/jquery/dist/jquery.js"></script>
<script src="~/lib/jquery-validation/dist/jquery.validate.min.js"></script>
<script src="~/lib/jquery-validation/dist/jquery.validate.js"></script>
<script src="~/lib/jquery-validation-unobtrusive/jquery.validate.unobtrusive.min.js"></script>
<script src="~/lib/jquery-validation-unobtrusive/jquery.validate.unobtrusive.js"></script>







Step 9.2 Login View

@model WebAuthentication_UsingSessing.Models.LoginSignUpViewModel
@{
    ViewData["Title"] = "Login";
    Layout = "~/Views/Shared/_Layout_Login.cshtml";
}

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<link href="~/css/login-signup.css" rel="stylesheet" />

<div class="container">
    <div class="row justify-content-center">
        <div class="col-lg-6 col-md-8">
            <div class="form-container">
                <div class="header">
                    <h1>Welcome Back</h1>
                    <p>Sign in to access your account</p>
                </div>

                <!-- Social Login Options -->
                <div class="social-login">
                    <a href="#" class="social-btn google">
                        <i class="fab fa-google"></i>
                    </a>
                    <a href="#" class="social-btn facebook">
                        <i class="fab fa-facebook-f"></i>
                    </a>
                    <a href="#" class="social-btn twitter">
                        <i class="fab fa-twitter"></i>
                    </a>
                </div>

                <div class="divider">or login with email</div>

                <h6 class="text-success text-center">@TempData["successMessage"]</h6>

                <form method="post" action="#">
                    <!-- Email -->
                    <div class="mb-4">
                        <label class="form-label">Username</label>
                        <div class="input-group">
                            <input asp-for="Username" type="text" class="form-control" placeholder="Enter Username">
                            <span class="icon"><i class="fas fa-envelope"></i></span>
                        </div>
                        <span class="text-danger">@TempData["errorUsername"]</span>
                    </div>

                    <!-- Password -->
                    <div class="mb-4">
                        <label class="form-label">Password</label>
                        <div class="input-group">
                            <input asp-for="Password" type="password" class="form-control" placeholder="Enter your password">
                            <span class="icon password-toggle"><i class="fas fa-eye"></i></span>
                        </div>
                        <span class="text-danger">@TempData["errorPassword"]</span>
                    </div>

                    <div class="forgot-password">
                        <a asp-action="ForgotPassword">Forgot your password?</a>
                        <br />
                        <a asp-action="ForgotUsername">Forgot your Username?</a>
                    </div>

                    <!-- Remember me -->
                    <div class="checkbox-container">
                        <input asp-for="IsRemember" type="checkbox" id="rememberMe" checked>
                        <label for="rememberMe">Remember me</label>
                    </div>

                    <!-- Submit Button -->
                    <div class="d-grid">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-sign-in-alt me-2"></i>Login
                        </button>
                    </div>
                </form>

                <!-- Signup Link -->
                <div class="login-link">
                    Don't have an account? <a asp-action="SignUp">Sign Up</a>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    // Password toggle functionality
    document.querySelectorAll('.password-toggle').forEach(function (toggle) {
        toggle.addEventListener('click', function () {
            const input = this.closest('.input-group').querySelector('input');
            const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
            input.setAttribute('type', type);

            // Toggle eye icon
            this.querySelector('i').classList.toggle('fa-eye');
            this.querySelector('i').classList.toggle('fa-eye-slash');
        });
    });
</script>





Step 9.3 AdminPanel (GetData) View

@model IEnumerable<WebAuthentication_UsingSessing.Models.Users>
@{
	ViewData["Title"] = "GetData";
	Layout = "~/Views/Shared/_Layout.cshtml";
}
@if (User.Identity.Name == "Meet")
{
	<h4 style="float:right;"><a asp-controller="Account" asp-action="SignUp" class="btn btn-primary">Add Users</a></h4>

	<div class="col-md-12">
		<table class="table table-bordered" id="myTable">

			<thead>
				<tr>
					<th>Id</th>
					<th>User Name</th>
					<th>Email</th>
					<th>Mobile No.</th>

					<th>Password</th>
					<th>IsActive</th>
					<th class="text-center">Edit</th>
					<th class="text-center">Delete</th>
				</tr>
			</thead>
			<tbody>
				@if (Model != null && Model.Any())
				{
					foreach (var item in Model)
					{
						<tr>
							@if (item.IsActive == false)
							{
								<td class="text-danger">@item.Id</td>
								<td class="text-danger">@item.UserName</td>
								<td class="text-danger">@item.Email</td>
								<td class="text-danger">@item.Mobile</td>
								<td class="text-danger">@item.Password</td>
								<td class="text-danger">Not Active</td>
								<td class="text-center">
									<div class="w-75 btn-group" role="group">
										<a class="btn btn-primary" asp-action="Edit" asp-route-id="@item.Id">
											<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-pencil-square" viewBox="0 0 16 16">
												<path d="M15.502 1.94a.5.5 0 0 1 0 .706L14.459 3.69l-2-2L13.502.646a.5.5 0 0 1 .707 0l1.293 1.293zm-1.75 2.456-2-2L4.939 9.21a.5.5 0 0 0-.121.196l-.805 2.414a.25.25 0 0 0 .316.316l2.414-.805a.5.5 0 0 0 .196-.12l6.813-6.814z" />
												<path fill-rule="evenodd" d="M1 13.5A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-6a.5.5 0 0 0-1 0v6a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5H9a.5.5 0 0 0 0-1H2.5A1.5 1.5 0 0 0 1 2.5z" />
											</svg> Edit
										</a>
									</div>
								</td>
								<td class="text-center">
									<div class="w-75 btn-group" role="group">
										<a class="btn btn-danger" asp-action="DeleteUser" asp-route-id="@item.Id">
											<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-trash3-fill" viewBox="0 0 16 16">
												<path d="M11 1.5v1h3.5a.5.5 0 0 1 0 1h-.538l-.853 10.66A2 2 0 0 1 11.115 16h-6.23a2 2 0 0 1-1.994-1.84L2.038 3.5H1.5a.5.5 0 0 1 0-1H5v-1A1.5 1.5 0 0 1 6.5 0h3A1.5 1.5 0 0 1 11 1.5m-5 0v1h4v-1a.5.5 0 0 0-.5-.5h-3a.5.5 0 0 0-.5.5M4.5 5.029l.5 8.5a.5.5 0 1 0 .998-.06l-.5-8.5a.5.5 0 1 0-.998.06m6.53-.528a.5.5 0 0 0-.528.47l-.5 8.5a.5.5 0 0 0 .998.058l.5-8.5a.5.5 0 0 0-.47-.528M8 4.5a.5.5 0 0 0-.5.5v8.5a.5.5 0 0 0 1 0V5a.5.5 0 0 0-.5-.5" />
											</svg> Delete
										</a>
									</div>
								</td>
							}
							else
							{
								<td>@item.Id</td>
								<td>@item.UserName</td>
								<td>@item.Email</td>
								<td>@item.Mobile</td>
								<td>@item.Password</td>
								<td>Active</td>
								<td class="text-center">
									<div class="w-75 btn-group" role="group">
										<a class="btn btn-primary" asp-action="Edit" asp-route-id="@item.Id">
											<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-pencil-square" viewBox="0 0 16 16">
												<path d="M15.502 1.94a.5.5 0 0 1 0 .706L14.459 3.69l-2-2L13.502.646a.5.5 0 0 1 .707 0l1.293 1.293zm-1.75 2.456-2-2L4.939 9.21a.5.5 0 0 0-.121.196l-.805 2.414a.25.25 0 0 0 .316.316l2.414-.805a.5.5 0 0 0 .196-.12l6.813-6.814z" />
												<path fill-rule="evenodd" d="M1 13.5A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-6a.5.5 0 0 0-1 0v6a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5H9a.5.5 0 0 0 0-1H2.5A1.5 1.5 0 0 0 1 2.5z" />
											</svg> Edit
										</a>
									</div>
								</td>
								<td class="text-center">
									<div class="w-75 btn-group" role="group">
										<a class="btn btn-danger" asp-action="DeleteUser" asp-route-id="@item.Id">
											<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-trash3-fill" viewBox="0 0 16 16">
												<path d="M11 1.5v1h3.5a.5.5 0 0 1 0 1h-.538l-.853 10.66A2 2 0 0 1 11.115 16h-6.23a2 2 0 0 1-1.994-1.84L2.038 3.5H1.5a.5.5 0 0 1 0-1H5v-1A1.5 1.5 0 0 1 6.5 0h3A1.5 1.5 0 0 1 11 1.5m-5 0v1h4v-1a.5.5 0 0 0-.5-.5h-3a.5.5 0 0 0-.5.5M4.5 5.029l.5 8.5a.5.5 0 1 0 .998-.06l-.5-8.5a.5.5 0 1 0-.998.06m6.53-.528a.5.5 0 0 0-.528.47l-.5 8.5a.5.5 0 0 0 .998.058l.5-8.5a.5.5 0 0 0-.47-.528M8 4.5a.5.5 0 0 0-.5.5v8.5a.5.5 0 0 0 1 0V5a.5.5 0 0 0-.5-.5" />
											</svg> Delete
										</a>
									</div>
								</td>
							}

						</tr>
					}
				}
			</tbody>
		</table>

	</div>
}
else
{
	<tr>
		<td colspan="9" class="text-center">
			<div class="alert alert-danger" role="alert">
				<h4 class="alert-heading">Access Denied!</h4>
				<p>You are not authorized to view this page.</p>
				<hr>
				<p class="mb-0">Please contact the administrator if you believe this is an error.</p>
			</div>
		</td>
	</tr>
}



** Now You have Successfully Created Whole Login System with Admin Panel




