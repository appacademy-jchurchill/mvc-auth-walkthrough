using MvcAuthWalkthrough.FormModels;
using MvcAuthWalkthrough.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace MvcAuthWalkthrough.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        [AllowAnonymous]
        public ActionResult Login()
        {
            LoginFormModel formModel = new LoginFormModel();
            return View(formModel);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Login(LoginFormModel formModel)
        {
            if (ModelState.IsValidField("Email") && ModelState.IsValidField("Password"))
            {
                // TODO Get the user record from the database by their email.
                User user = new User()
                {
                    Email = "james@smashdev.com",
                    HashedPassword = "$2a$12$ctRHCe0fNXXNYz13JybBruMf40COXIhZWh8wLaVncPWIqJyYvbO8G"
                };

                // If we didn't get a user back from the database
                // or if the provided password doesn't match the password stored in the database
                // then login failed.
                if (user == null || !BCrypt.Net.BCrypt.Verify(formModel.Password, user.HashedPassword))
                {
                    ModelState.AddModelError("", "Login failed.");
                }
            }

            if (ModelState.IsValid)
            {
                // Login the user.
                FormsAuthentication.SetAuthCookie(formModel.Email, false);

                // Send them to the home page.
                return RedirectToAction("Index", "Home");
            }

            return View(formModel);
        }

        [AllowAnonymous]
        public ActionResult Register()
        {
            RegisterFormModel formModel = new RegisterFormModel();
            return View(formModel);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Register(RegisterFormModel formModel)
        {
            if (ModelState.IsValid)
            {
                // Hash the user's password.
                string hashedPassword = BCrypt.Net.BCrypt.HashPassword(formModel.Password, 12);

                // Create an instance of the user database model.
                User user = new User()
                {
                    Email = formModel.Email,
                    HashedPassword = hashedPassword,
                    Name = formModel.Name
                };

                // TODO Save the user to the database.

                // Create the authentication ticket (i.e. HTTP cookie).
                FormsAuthentication.SetAuthCookie(formModel.Email, false);

                // Redirect the user to the "Home" page.
                return RedirectToAction("Index", "Home");
            }

            return View(formModel);
        }

        [HttpPost]
        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();

            return RedirectToAction("Login");
        }
    }
}