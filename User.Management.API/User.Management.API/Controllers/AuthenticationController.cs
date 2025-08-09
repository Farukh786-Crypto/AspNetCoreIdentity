using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using User.Management.API.Models;
using User.Management.API.Models.Authentication.Login;
using User.Management.API.Models.Authentication.SignUp;
using User.Management.Service.Models;
using User.Management.Service.Services;

namespace User.Management.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;

        public AuthenticationController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,IEmailService emailService, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _configuration = configuration;
        }

        [HttpPost]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterUser registerUser,string role)
        {
            // first we check user is already present or not
            var user = await _userManager.FindByEmailAsync(registerUser.Email);
            if(user!=null)
            {
                // if user is already present then return bad request
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response
                    {
                        Status = "Error",
                        Message = "User already exists"
                    });
            }
            // if the user does not exit then add user in the database
            IdentityUser newUser = new IdentityUser
            {
                UserName = registerUser.UserName,
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString()
            };
            if (await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(newUser, registerUser.Password);
                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response
                    {
                        Status = "Error",
                        Message = "User creation failed"
                    });
                }
                // assign the role for this new user
                await _userManager.AddToRoleAsync(newUser, role);

                // Add Token to verify the email ...
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication",
                    new { token = token, email = registerUser.Email }, Request.Scheme);
                // Send Email to the user
                var message = new Message(new string[] { registerUser.Email }, "Confirm your email",
                    $"<h1>Click the link to confirm your email</h1><br/><a href='{confirmationLink}'>Click here to confirm</a>");

                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                    new Response
                    {
                        Status = "Success",
                        Message = $"User Createred & Email sent to {registerUser.Email} Sucessfully"
                    });
            }
            else
            {
                return StatusCode(StatusCodes.Status404NotFound,
                    new Response
                    {
                        Status = "Error",
                        Message = "Role does not exist"
                    });
            }
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
            // cheking the user ..
            var user = await _userManager.FindByNameAsync(loginModel.UserName);

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
            return Unauthorized();

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
