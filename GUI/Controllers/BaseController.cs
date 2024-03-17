using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace GUI.Controllers
{
    // BaseController acts as a foundation for other controllers.
    // It includes common functionality that's shared across different controllers.
    public class BaseController : Controller
    {
        // This method is called before the execution of an action method in any controller that inherits from BaseController.
        public override void OnActionExecuting(ActionExecutingContext context)
        {
            base.OnActionExecuting(context); // Calls the base implementation of OnActionExecuting to ensure any base logic is executed.

            // Retrieves the username from the session.
            var username = HttpContext.Session.GetString("Username");

            // If the username exists, it's added to ViewBag to be accessible in the views.
            // This is useful for displaying the username or customizing the user experience based on the logged-in user.
            if (!string.IsNullOrEmpty(username))
            {
                ViewBag.Username = username;
            }
        }
    }
}
