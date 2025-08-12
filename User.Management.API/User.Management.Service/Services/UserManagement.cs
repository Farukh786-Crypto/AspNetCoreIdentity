using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Asn1.Ocsp;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using User.Management.Service.Models;
using User.Management.Service.Models.Authentication.Login;
using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Models.Authentication.User;

namespace User.Management.Service.Services
{
    public class UserManagement : IUserManagement
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserManagement(UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            RoleManager<IdentityRole> roleManager, IEmailService emailService, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }

        public async Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser)
        {
            // first we check user is already present or not
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
            {
                // if user is already present then return bad request
                return new ApiResponse<CreateUserResponse>
                {
                    IsSuccess = false,
                    StatusCode = StatusCodes.Status403Forbidden,
                    Message = "User already exists",
                };
            }
            // if the user does not exit then add user in the database
            IdentityUser newUser = new IdentityUser
            {
                UserName = registerUser.UserName,
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                TwoFactorEnabled = true
            };
            var result = await _userManager.CreateAsync(newUser, registerUser.Password);
            if (result.Succeeded)
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
                return new ApiResponse<CreateUserResponse>
                {
                    Response = new CreateUserResponse() { Token=token,User=newUser},
                    IsSuccess = true,
                    StatusCode = StatusCodes.Status201Created,
                    Message = "User created successfully"
                };
            }
            else
            {
                // if user is created successfully then generate the token for this user
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
                return new ApiResponse<CreateUserResponse>
                {
                    IsSuccess = true,
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Message = "User Failed to create",
                };
            }
        }
        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles,IdentityUser user)
        {
            var assignedRoles = new List<string>();
            foreach (var role in roles)
            {
                if(await _roleManager.RoleExistsAsync(role))
                {
                    // if user role is already present in the database then skip it
                    if (!await _userManager.IsInRoleAsync(user, role))
                    {
                        // assign the role for this new user
                        await _userManager.AddToRoleAsync(user, role);
                        assignedRoles.Add(role);
                    }
                    
                }
            }
            return new ApiResponse<List<string>>
            {
                IsSuccess = true,
                StatusCode = StatusCodes.Status200OK,
                Message = "Roles assigned successfully",
                Response = assignedRoles
            };
        }

        public async Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(LoginModel loginModel)
        {
            // cheking the user ..
            var user = await _userManager.FindByNameAsync(loginModel.UserName);
            if (user != null)
            {
                // first log out
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);
                if (user.TwoFactorEnabled)
                {
                    var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                    return new ApiResponse<LoginOtpResponse>
                    {
                        Response = new LoginOtpResponse
                        {
                            User = user,
                            IsTwoFactorEnabled = user.TwoFactorEnabled,
                            Token = token
                        },
                        IsSuccess = true,
                        StatusCode = StatusCodes.Status200OK,
                        Message = $"We have sent an OTP to your Email {user.Email}"
                    };
                }
                else
                {
                    return new ApiResponse<LoginOtpResponse>
                    {
                        Response = new LoginOtpResponse
                        {
                            User = user,
                            Token = String.Empty,
                            IsTwoFactorEnabled = user.TwoFactorEnabled,
                        },
                        IsSuccess = true,
                        StatusCode = StatusCodes.Status200OK,
                        Message = "Two Factor Authentication (2FA) is not enabled for this user",
                    };
                }
            }
            else
            {
                return new ApiResponse<LoginOtpResponse>
                {
                   Response = new LoginOtpResponse
                   {
                       User = null,
                       Token = String.Empty,
                       IsTwoFactorEnabled = false
                   },
                    IsSuccess = false,
                    StatusCode = StatusCodes.Status404NotFound,
                    Message = "User not found. Please check your username and password."
                };
            }
        }
    }
}
