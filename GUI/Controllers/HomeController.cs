using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using GUI.Models;
using System.Text.Json;
using System.Reflection;
using GUI.ServicesMonolith;

namespace GUI.Controllers;


// HomeController inherits from BaseController and is responsible for handling requests related to the Home page and user actions.
public class HomeController : BaseController
{
    private readonly ILogger<HomeController> _logger; 

    public HomeController(ILogger<HomeController> logger)
    {
        _logger = logger;
    }

    // Returns the Index view (the home page).
    public IActionResult Index()
    {
        return View();
    }

    // Handles the login POST request, validates the user, and sets session variables.
    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Login(LoginViewModel login)
    {
        try
        {
            // Attempts to verify the user's credentials.
            var (isValidUser, key) = new VerifyMasterUser().InitializeOrVerifyMasterUser(login.Email, login.Password);

            // If verification is successful, set session variables and redirect to Dashboard.
            if (isValidUser && key != null)
            {
                HttpContext.Session.SetString("EncryptKey", key);
                HttpContext.Session.SetString("Username", login.Email);

                return RedirectToAction("Dashboard");
            }
            throw new InvalidLoginException(); // Throws an exception if login fails.
        }
        catch (InvalidLoginException e)
        {
            // Catches the login exception and returns to the Index view with an error message.
            ViewBag.ErrorMessage = e.Message;
            return View("Index");
        }
    }

    // Displays the Dashboard view if the user is logged in.
    public IActionResult Dashboard()
    {
        // Checks if the user is logged in by verifying session key.
        var userKey = HttpContext.Session.GetString("EncryptKey");
        if (string.IsNullOrEmpty(userKey))
        {
            return RedirectToAction("Index"); // Redirects to Index if not logged in.
        }
        return View("Success"); // Returns the Dashboard view.
    }

    // Returns the AddPassword view for adding a new password.
    public IActionResult AddPasswordView()
    {
        // Verifies if the user is logged in.
        var userKey = HttpContext.Session.GetString("EncryptKey");
        if (string.IsNullOrEmpty(userKey))
        {
            return RedirectToAction("Index");
        }
        var nullPassword = new PasswordSavings();
        return View("AddPassword", nullPassword);
    }

    // Handles the POST request to add a new password.
    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult AddPassword(PasswordSavings model)
    {
        if (ModelState.IsValid) // Validates the model.
        {
            var keyString = HttpContext.Session.GetString("EncryptKey");
            if (string.IsNullOrEmpty(keyString))
            {
                return RedirectToAction("Index");
            }

            // Encrypts the password and adds it to storage.
            var key = Convert.FromBase64String(keyString);
            byte[] iv;
            var encryptedPassword = EncryptionService.EncryptData(model.Password, key, out iv);

            var managementService = new VerifyMasterUser();
            managementService.AddEncryptedPassword(Convert.ToBase64String(encryptedPassword), Convert.ToBase64String(iv));

            TempData["SuccessMessage"] = "Password has been successfully added!";

            return RedirectToAction("Dashboard");
        }
        return View(model); // Returns the view with the model if validation fails.
    }

    // Shows decrypted passwords if the user is logged in.
    public IActionResult ShowPasswords()
    {
        var keyString = HttpContext.Session.GetString("EncryptKey");
        if (string.IsNullOrEmpty(keyString))
        {
            return RedirectToAction("Index");
        }

        var key = Convert.FromBase64String(keyString);
        var passwordShowing = new VerifyMasterUser();
        var passwords = passwordShowing.GetDecryptedPasswords(key);

        ViewBag.DecryptedPasswords = passwords; // Sends decrypted passwords to the view.
        return View("ShowPassword");
    }

    // Returns a decrypted password for a given index if the user is logged in.
    [HttpGet]
    public IActionResult GetDecryptedPassword(int index)
    {
        var keyString = HttpContext.Session.GetString("EncryptKey");
        if (string.IsNullOrEmpty(keyString))
        {
            return Unauthorized(); // Returns unauthorized if the user is not logged in.
        }

        var key = Convert.FromBase64String(keyString);
        var passwordShowing = new VerifyMasterUser();
        var password = passwordShowing.GetDecryptedPasswordAt(index, key);

        return Content(password); // Returns the decrypted password as content.
    }

    // Returns the GeneratePassword view.
    public IActionResult GeneratePasswordView()
    {
        var keyString = HttpContext.Session.GetString("EncryptKey");
        if (string.IsNullOrEmpty(keyString))
        {
            return RedirectToAction("Index");
        }

        return View("GeneratePassword");
    }

    // Handles the generation of a new password based on user-defined options.
    public IActionResult GeneratePassword(PasswordOptions model)
    {
        var keyString = HttpContext.Session.GetString("EncryptKey");
        if (string.IsNullOrEmpty(keyString))
        {
            return RedirectToAction("Index");
        }
        if (model.PasswordLength < 8 || model.PasswordLength > 128)
        {
            ModelState.AddModelError("PasswordLength", "Password length must be between 8 and 128 characters.");
            return View("GeneratePassword");
        }

        var passwordGenerator = PasswordGenerator.GeneratePassword(model.PasswordLength, model.IncludeSpecialChars);
        ViewBag.GeneratedPassword = passwordGenerator; // Sends the generated password to the view.

        return View("GeneratePassword");
    }

    // Clears the user's session and logs them out.
    public IActionResult Logout()
    {
        HttpContext.Session.Clear();

        return RedirectToAction("Index");
    }

    // Returns the Privacy view.
    public IActionResult Privacy()
    {
        return View();
    }

    // Returns the Error view in case of an error.
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
