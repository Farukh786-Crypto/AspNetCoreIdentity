using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.Ocsp;
using System;
using System.Collections.Generic;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using User.Management.Data.Models;
using User.Management.Service.Models;
using User.Management.Service.Models.Authentication.Login;
using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Models.Authentication.User;

namespace User.Management.Service.Services
{
    public class UserManagement : IUserManagement
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public UserManagement(UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<IdentityRole> roleManager, IEmailService emailService, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _configuration = configuration;
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
            ApplicationUser newUser = new ApplicationUser
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

        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles,ApplicationUser user)
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

        public async Task<ApiResponse<LoginResponse>> GetJwtTokenAsync(ApplicationUser user)
        {
            // claimlist creation
            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

            // we add role to the list
            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }
            // generate the token with claims ..
            var jwtToken = GetToken(authClaims); //access token
            var refreshToken = GenerateRefreshToken();
            // We use '_' to discard the boolean result of int.TryParse, since we only need the parsed value in 'refreshTokenValidity'.
            _ = int.TryParse(_configuration["JWT:RefreshTokenValidity"], out int refreshTokenValidity);
            // Saving refresh token and its expiry for the user
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(refreshTokenValidity);
            // Updating the user in the database
            await _userManager.UpdateAsync(user);

            return new ApiResponse<LoginResponse>
            {
                Response = new LoginResponse()
                {
                    AccessToken = new TokenType()
                    {
                        Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        ExpiryTokenDate = jwtToken.ValidTo
                    },
                    RefreshToken = new TokenType()
                    {
                        Token = user.RefreshToken,
                        ExpiryTokenDate = (DateTime)user.RefreshTokenExpiry
                    }
                },

                IsSuccess = true,
                StatusCode = 200,
                Message = $"Token created"
            };
        }

        public async Task<ApiResponse<LoginResponse>> LoginUserWithJWTokenAsync(string otp, string userName)
        {
            var user = await _userManager.FindByNameAsync(userName);
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", otp, false, false);
            if (signIn.Succeeded)
            {
                if (user != null)
                {
                    return await GetJwtTokenAsync(user);
                }
            }
            return new ApiResponse<LoginResponse>()
            {

                Response = new LoginResponse()
                {

                },
                IsSuccess = false,
                StatusCode = 400,
                Message = $"Invalid Otp"
            };
        }

        public async Task<ApiResponse<LoginResponse>> RenewAccessTokenAsync(LoginResponse tokens)
        {
            var accessToken = tokens.AccessToken;
            var refreshToken = tokens.RefreshToken;
            var principal = GetClaimsPrincipal(accessToken.Token);
            var user = await _userManager.FindByNameAsync(principal.Identity.Name);
            if (refreshToken.Token != user.RefreshToken && refreshToken.ExpiryTokenDate <= DateTime.Now)
            {
                return new ApiResponse<LoginResponse>
                {

                    IsSuccess = false,
                    StatusCode = 400,
                    Message = $"Token invalid or expired"
                };
            }
            var response = await GetJwtTokenAsync(user);
            return response;
        }

        #region PrivateMethods
        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            _ = int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);
            var expirationTimeUtc = DateTime.UtcNow.AddMinutes(tokenValidityInMinutes);
            var localTimeZone = TimeZoneInfo.Local;
            var expirationTimeInLocalTimeZone = TimeZoneInfo.ConvertTimeFromUtc(expirationTimeUtc, localTimeZone);

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: expirationTimeInLocalTimeZone,
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }
        private string GenerateRefreshToken()
        {
            var randomNumber = new Byte[64];
            var range = RandomNumberGenerator.Create();
            range.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private ClaimsPrincipal GetClaimsPrincipal(string accessToken)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken securityToken);

            return principal;

        }
        #endregion
    }
}
