using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BCrypt.Net;

var builder = WebApplication.CreateBuilder(args);

// JWT Configuration
var jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? "dev_secret_change_me";
var jwtIssuer = Environment.GetEnvironmentVariable("JWT_ISSUER") ?? "streakup-auth";
var jwtAudience = Environment.GetEnvironmentVariable("JWT_AUDIENCE") ?? "streakup-clients";

// In-memory stores
var users = new ConcurrentDictionary<string, User>();
var tokenBlacklist = new ConcurrentDictionary<string, bool>();
var rateLimitStore = new ConcurrentDictionary<string, (int count, DateTime windowStart)>();

// User model
record User(string Id, string Username, string Email, string PasswordHash);

// Rate limiting middleware
app.Use(async (context, next) =>
{
    var clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var now = DateTime.UtcNow;
    var windowStart = now.AddMinutes(-1); // 1 minute window
    
    var (count, window) = rateLimitStore.GetOrAdd(clientIp, (0, now));
    
    // Reset window if expired
    if (window < windowStart)
    {
        rateLimitStore.TryUpdate(clientIp, (1, now), (count, window));
    }
    else
    {
        // Check if limit exceeded
        if (count >= 60)
        {
            context.Response.StatusCode = 429;
            await context.Response.WriteAsJsonAsync(new { error = "Too many requests" });
            return;
        }
        
        // Increment counter
        rateLimitStore.TryUpdate(clientIp, (count + 1, window), (count, window));
    }
    
    await next();
});

// Add services to the container.
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// JWT Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret)),
            ClockSkew = TimeSpan.Zero
        };
        
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = context =>
            {
                var token = context.SecurityToken as JwtSecurityToken;
                if (token != null && tokenBlacklist.ContainsKey(token.RawData))
                {
                    context.Fail("Token has been revoked");
                }
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

// Helper function to generate JWT token
string GenerateJwtToken(string userId, string username)
{
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
    var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    
    var claims = new[]
    {
        new Claim("sub", userId),
        new Claim("name", username)
    };
    
    var token = new JwtSecurityToken(
        issuer: jwtIssuer,
        audience: jwtAudience,
        claims: claims,
        expires: DateTime.UtcNow.AddHours(1),
        signingCredentials: credentials
    );
    
    return new JwtSecurityTokenHandler().WriteToken(token);
}

// Health check endpoint
app.MapGet("/healthz", () => "OK")
    .WithName("HealthCheck")
    .WithOpenApi();

// Register endpoint
app.MapPost("/api/auth/register", (RegisterRequest request) =>
{
    if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
    {
        return Results.BadRequest(new { error = "Username, email, and password are required" });
    }
    
    if (users.ContainsKey(request.Username))
    {
        return Results.Conflict(new { error = "Username already exists" });
    }
    
    var userId = Guid.NewGuid().ToString();
    var passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);
    var user = new User(userId, request.Username, request.Email, passwordHash);
    
    users.TryAdd(request.Username, user);
    
    return Results.Ok(new { message = "User registered successfully", userId });
})
.WithName("Register")
.WithOpenApi();

// Login endpoint
app.MapPost("/api/auth/login", (LoginRequest request) =>
{
    if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
    {
        return Results.BadRequest(new { error = "Username and password are required" });
    }
    
    if (!users.TryGetValue(request.Username, out var user))
    {
        return Results.Unauthorized();
    }
    
    if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
    {
        return Results.Unauthorized();
    }
    
    var token = GenerateJwtToken(user.Id, user.Username);
    
    return Results.Ok(new { accessToken = token, expiresIn = 3600 });
})
.WithName("Login")
.WithOpenApi();

// Logout endpoint
app.MapPost("/api/auth/logout", (HttpContext context) =>
{
    var token = context.Request.Headers.Authorization.FirstOrDefault()?.Split(" ").Last();
    if (!string.IsNullOrEmpty(token))
    {
        tokenBlacklist.TryAdd(token, true);
    }
    
    return Results.Ok(new { message = "Logged out successfully" });
})
.WithName("Logout")
.RequireAuthorization()
.WithOpenApi();

// Me endpoint
app.MapGet("/api/auth/me", (HttpContext context) =>
{
    var userId = context.User.FindFirst("sub")?.Value;
    var username = context.User.FindFirst("name")?.Value;
    
    if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(username))
    {
        return Results.Unauthorized();
    }
    
    return Results.Ok(new { id = userId, username });
})
.WithName("Me")
.RequireAuthorization()
.WithOpenApi();

app.Run();

// Request models
record RegisterRequest(string Username, string Email, string Password);
record LoginRequest(string Username, string Password);