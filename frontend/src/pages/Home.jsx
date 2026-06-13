import React from 'react'
import { Link } from 'react-router-dom'
import './Home.css'

export default function Home() {
  return (
    <div className="home">
      <section className="hero">
        <div className="container">
          <h1>Welcome to CloudCart</h1>
          <p className="hero-subtitle">
            Cloud-native e-commerce built for DevSecOps training.
            Discover products, manage your cart, and experience intentional security findings.
          </p>
          <div className="hero-actions">
            <Link to="/products" className="btn btn-primary btn-lg">Shop Now</Link>
            <Link to="/register" className="btn btn-outline btn-lg">Create Account</Link>
          </div>
        </div>
      </section>
      <section className="features container">
        <div className="feature-card card">
          <h3>Shopping Cart</h3>
          <p>Add products, manage quantities, and checkout seamlessly.</p>
        </div>
        <div className="feature-card card">
          <h3>Reviews</h3>
          <p>Share your experience with product reviews and ratings.</p>
        </div>
        <div className="feature-card card">
          <h3>Order Tracking</h3>
          <p>View order history and track delivery status.</p>
        </div>
        <div className="feature-card card">
          <h3>User Profiles</h3>
          <p>Manage your account settings and preferences.</p>
        </div>
      </section>
      <section className="warning-banner">
        <div className="container">
          <strong>Training Application:</strong> This app contains intentional vulnerabilities for DevSecOps pipeline testing.
        </div>
      </section>
    </div>
  )
}
