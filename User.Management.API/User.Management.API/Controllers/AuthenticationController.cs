using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using User.Management.API.Models;
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

        public AuthenticationController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,IEmailService emailService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
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
                return StatusCode(StatusCodes.Status201Created,
                    new Response
                    {
                        Status = "Success",
                        Message = "User created successfully"
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

        [HttpGet]
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
        }
    }
}
