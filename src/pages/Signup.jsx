import { useState } from 'react'
import { Link } from 'react-router-dom'

// Provide account registration and notify the application when signup succeeds.
function Signup({ onAuthSuccess }) {
    const [email, setEmail] = useState('')
    const [displayName, setDisplayName] = useState('')
    const [password, setPassword] = useState('')
    const [error, setError] = useState('')
    const [submitting, setSubmitting] = useState(false)

    // Submit registration details without reloading the page.
    async function handleSubmit(event) {
        event.preventDefault()

        if (submitting) return

        setError('')
        setSubmitting(true)

        try {
            const response = await fetch('/api/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify({
                    email: email.trim(),
                    displayName: displayName.trim(),
                    password,
                }),
            })

            // Read the response for either the new user or a validation error.
            const data = await response.json()

            if (!response.ok) {
                throw new Error(
                    data.error || `Registration failed: ${response.status}`,
                )
            }

            if (!data.user) {
                throw new Error('Registration succeeded, but no user was returned.')
            }

            // Registration also creates a session on the backend.
            setPassword('')
            onAuthSuccess(data.user)
        } catch (requestError) {
            setError(
                requestError instanceof Error
                    ? requestError.message
                    : 'An unexpected error occurred.',
            )
        } finally {
            setSubmitting(false)
        }
    }

    return (
        <section className="auth-card">
            <h1>Create an Account</h1>
            <p>Sign up to save your quiz results and track your progress.</p>

            <form onSubmit={handleSubmit}>
                <div>
                    <label htmlFor="signup-email">Email</label>
                    <input
                        id="signup-email"
                        type="email"
                        name="email"
                        autoComplete="email"
                        value={email}
                        onChange={(event) => setEmail(event.target.value)}
                        disabled={submitting}
                        required
                    />
                </div>

                <div>
                    <label htmlFor="signup-display-name">Display Name</label>
                    <input
                        id="signup-display-name"
                        type="text"
                        name="displayName"
                        autoComplete="nickname"
                        maxLength={40}
                        value={displayName}
                        onChange={(event) => setDisplayName(event.target.value)}
                        disabled={submitting}
                        required
                    />
                </div>

                <div>
                    <label htmlFor="signup-password">Password</label>
                    <input
                        id="signup-password"
                        type="password"
                        name="password"
                        autoComplete="new-password"
                        minLength={8}
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        disabled={submitting}
                        required
                    />
                </div>

                <button
                    className="button"
                    type="submit"
                    disabled={submitting}
                >
                    {submitting ? 'Creating Account...' : 'Create Account'}
                </button>

                {error && (
                    <p className="message error" role="alert">
                        {error}
                    </p>
                )}
            </form>

            {/* Direct existing users to the login page. */}
            <p>
                Already have an account?{' '}
                <Link className="link-button" to="/login">
                    Login
                </Link>
            </p>
        </section>
    )
}

export default Signup