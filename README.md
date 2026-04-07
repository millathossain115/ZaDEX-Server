# ZaDEX Server

ZaDEX Server is the robust Express.js and MongoDB backend fueling the ZaDEX Parcel Delivery System. It provides secure RESTful APIs for managing users, parcels, riders, and administrative functions, alongside role-based access control and JWT-based authentication.

## 🚀 Features

- **Role-Based Access Control (RBAC):** Distinct authentication and authorization layers for Users, Riders, and Admins.
- **Secure Authentication:** JWT (JSON Web Tokens) via HTTP-only cookies, combined with bcrypt for password hashing.
- **Parcel Management:** Create, track, update, and manage parcels from pickup to delivery.
- **Rider Operations:** Endpoints for new rider applications, status tracking, and delivery management.
- **Admin Dashboard Controls:** Total oversight endpoints for user roles, parcel assignments, and system-wide monitoring.
- **Payment Integration:** Manage parcel payment statuses and handle transaction/tracking IDs.

## 🛠️ Technology Stack

- **Runtime:** [Node.js](https://nodejs.org/)
- **Framework:** [Express.js](https://expressjs.com/) v5
- **Database:** [MongoDB](https://www.mongodb.com/) (using native MongoDB driver)
- **Authentication:** `jsonwebtoken` & `bcrypt`
- **Other Utilities:** `cookie-parser`, `cors`, `dotenv`

## ⚙️ Dependencies

- `express`
- `mongodb`
- `jsonwebtoken`
- `bcrypt`
- `cors`
- `cookie-parser`
- `dotenv`

## 🔐 Environment Variables

To run this project securely, you will need to add the following environment variables to your `.env` file at the root of your project:

```env
PORT=5000
MONGODB_URI=your_mongodb_connection_string
ACCESS_TOKEN_SECRET=your_jwt_secret_key
ADMIN_SETUP_SECRET=your_secret_for_initial_admin_setup
NODE_ENV=development
```

## 🛠️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd ZaDex_Server
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure the environment:**
   - Create a `.env` file in the root directory.
   - Add all required variables as detailed in the Environment Variables section above.

4. **Start the development server:**
   ```bash
   npm run dev
   # OR
   nodemon index.js
   ```

5. The server will start running on the port specified in your `.env` (default: 5000).

## 📡 API Endpoints Overview

Here's a brief overview of the main route categories:

- **Auth:**
  - `POST /jwt` - Generate HTTP-only token upon login
  - `POST /logout` - Clear authentication token
  
- **Parcels:**
  - `GET /parcels` - Fetch user's parcels
  - `POST /parcels` - Create a new parcel request
  - `GET /parcels/track/:trackingId` - Track a parcel
  
- **Riders:**
  - `POST /rider-applications` - Apply to become a rider
  - `GET /rider/parcels` - Fetch assigned deliveries (Rider only)
  - `PUT /parcels/status/:id` - Update delivery status (Rider only)

- **Admin:**
  - `GET /all-parcels` - View and search all system parcels
  - `PATCH /users/make-admin/:id` - Promote a user
  - `PATCH /rider-applications/:id` - Approve/Reject rider applications

*Note: Most routes require a valid JWT token. Access to admin or rider routes requires appropriate verified roles.*

## 📄 License

This project is licensed under the ISC License.
