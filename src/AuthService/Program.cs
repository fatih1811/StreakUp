var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Health check endpoint
app.MapGet("/healthz", () => "OK")
    .WithName("HealthCheck")
    .WithOpenApi();

// Auth endpoints
app.MapPost("/api/auth/register", () => new { message = "stub register" })
    .WithName("Register")
    .WithOpenApi();

app.MapPost("/api/auth/login", () => new { message = "stub login" })
    .WithName("Login")
    .WithOpenApi();

app.Run();