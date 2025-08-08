using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace User.Management.API.Migrations
{
    /// <inheritdoc />
    public partial class RolesSeeded : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "7286a7ef-093c-436d-a263-da784c7cddf6", "2", "User", "User" },
                    { "8651fbc1-8a6f-4fd8-842c-32b1029d0cb0", "3", "HR", "HR" },
                    { "989e3b67-5509-4d5d-ab2d-f64aad23fa1c", "1", "Admin", "Admin" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "7286a7ef-093c-436d-a263-da784c7cddf6");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "8651fbc1-8a6f-4fd8-842c-32b1029d0cb0");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "989e3b67-5509-4d5d-ab2d-f64aad23fa1c");
        }
    }
}
