using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using User.Management.API.Models;
using User.Management.Service.Models;
using User.Management.Service.Models.Authentication.Login;
using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Services;

namespace User.Management.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IUserManagement _user;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;

        public AuthenticationController(UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,IUserManagement user,
            RoleManager<IdentityRole> roleManager,IEmailService emailService, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _user = user;
            _roleManager = roleManager;
            _emailService = emailService;
            _configuration = configuration;
        }

        [HttpPost]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterUser registerUser)
        {
            var tokenResponse = await _user.CreateUserWithTokenAsync(registerUser);
            if (tokenResponse.IsSuccess)
            {
                await _user.AssignRoleToUserAsync(registerUser.Role,tokenResponse.Response.User);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { tokenResponse.Response.Token, email = registerUser.Email }, Request.Scheme);
                var message = new Message(new string[] { registerUser.Email! }, "Confirmation email Link", confirmationLink!);
                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                    new Response
                    {
                        Status = "Success",
                        Message = $"User created successfully. Please check your email {registerUser.Email} for confirmation link.",
                        IsSuccess = true
                    });
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
               new Response
               {
                   Message = tokenResponse.Message,
                   IsSuccess = tokenResponse.IsSuccess,
               });
        }

        /* [HttpGet]
         public IActionResult TestEmail()
         {
             var message = new Message(new string[] { "shaikhfarukh600@gmail.com" }, "Test", "<h1>Subscribe to my youtube channel</h1>");
             _emailService.SendEmail(message);
             return StatusCode(StatusCodes.Status200OK,
                 new Response
                 {
                     Status = "Success",
                     Message = "Email sent successFully !!"
                 });
         }*/

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token,string email)
        {
           var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return StatusCode(StatusCodes.Status404NotFound,
                    new Response
                    {
                        Status = "Error",
                        Message = "User not found"
                    });
            }
            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                return StatusCode(StatusCodes.Status200OK,
                    new Response
                    {
                        Status = "Success",
                        Message = "Email confirmed successfully"
                    });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response
                    {
                        Status = "Error",
                        Message = "Email confirmation failed"
                    });
            }
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var loginOtpResponse = await _user.GetOtpByLoginAsync(loginModel);
            if(loginOtpResponse.Response!=null)
            {
                // cheking the user ..
                var user = loginOtpResponse.Response.User;
                if (user.TwoFactorEnabled)
                {
                    var token = loginOtpResponse.Response.Token;
                    var message = new Message(new string[] { user.Email! }, "OTP Confirmation",
                        $"<h1>Your OTP is {token}</h1><br/><p>Use this OTP to login</p>");
                    _emailService.SendEmail(message);
                    return
                        StatusCode(StatusCodes.Status200OK,
                        new Response
                        {
                            IsSuccess = loginOtpResponse.IsSuccess,
                            Status = "Sucess",
                            Message = $"We have sent an OTP to your Email {user.Email}"
                        });
                }

                // cheking the password of user
                if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
                {
                    // claimlist creation
                    var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                    // we add role to the list
                    var roles = await _userManager.GetRolesAsync(user);
                    foreach (var role in roles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }

                    // generate the token with claims ..
                    var jwtToken = GetToken(authClaims);

                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        expiration = jwtToken.ValidTo
                    });

                    // return the token ..
                }
            }
            return Unauthorized();
        }

        [HttpPost]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code,string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            var signIn = _signInManager.TwoFactorSignInAsync("Email", code, isPersistent: false, rememberClient: false);
            if(signIn.IsCompletedSuccessfully)
            {
                // cheking the password of user
                if (user != null)
                {
                    // claimlist creation
                    var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                    // we add role to the list
                    var roles = await _userManager.GetRolesAsync(user);
                    foreach (var role in roles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }

                    // generate the token with claims ..
                    var jwtToken = GetToken(authClaims);

                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        expiration = jwtToken.ValidTo
                    });

                    // return the token ..
                }
            }
            return StatusCode(StatusCodes.Status403Forbidden,
                new Response
                {
                    Status = "Error",
                    Message = $"Invalid OTP to your Email {user.Email}"
                });
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("ForgotPassword")]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                // create token
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var forgotPasswordlink = Url.Action(nameof(ResetPassword), "Authentication", new { token, email = user.Email }, Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Forgot Password email link", forgotPasswordlink!);
                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Sucess", Message = $"Password Changed request is sent on Email {user.Email}. Please Open your email & click the link." });
            }
            return StatusCode(StatusCodes.Status400BadRequest,
                new Response { Status = "Error", Message = $"Couldn't send link to email, please try again ... " });
        }

        [HttpGet("reset-password")]
        public async Task<IActionResult> ResetPassword(string token,string email)
        {
            var model = new ResetPassword { Token = token, Email = email  };
            return Ok(new{
                model
            });
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user != null)
            {
                // reset password
                var resetPassResult = await _userManager.ResetPasswordAsync(user,resetPassword.Token,resetPassword.Password);
                if (!resetPassResult.Succeeded) {
                    foreach (var error in resetPassResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                    return Ok(resetPassResult);
                }
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Sucess", Message = $"Password Changed." });
            }
            return StatusCode(StatusCodes.Status400BadRequest,
                new Response { Status = "Error", Message = $"Couldn't send link to email, please try again ... " });
        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return token;
        }
    }
}
