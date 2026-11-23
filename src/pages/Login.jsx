import { useState } from 'react'
import { Link } from 'react-router-dom'

// Allow existing users to sign in through the authentication API.
function Login({ onAuthSuccess }) {
    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const [error, setError] = useState('')
    const [submitting, setSubmitting] = useState(false)

    // Submit credentials and update the application's authentication state.
    async function handleSubmit(event) {
        event.preventDefault()

        if (submitting) return

        setError('')
        setSubmitting(true)

        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify({
                    email: email.trim(),
                    password,
                }),
            })

            // Read the response for either user information or an API error.
            const data = await response.json()

            if (!response.ok) {
                throw new Error(data.error || `Login failed: ${response.status}`)
            }

            if (!data.user) {
                throw new Error('Login succeeded, but no user was returned.')
            }

            // The backend creates the session; React stores the public user data.
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
        <section>
            <h1>Login</h1>
            <p>Sign in to access your Quizzy account.</p>

            <form onSubmit={handleSubmit}>
                <div>
                    <label htmlFor="login-email">Email</label>
                    <input
                        id="login-email"
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
                    <label htmlFor="login-password">Password</label>
                    <input
                        id="login-password"
                        type="password"
                        name="password"
                        autoComplete="current-password"
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
                    {submitting ? 'Logging in...' : 'Login'}
                </button>

                {error && (
                    <p className="message error" role="alert">
                        {error}
                    </p>
                )}
            </form>

            {/* Direct new players to the account registration page. */}
            <p>
                Don't have an account?{' '}
                <Link className="link-button" to="/signup">
                    Sign Up
                </Link>
            </p>
        </section>
    )
}

export default Login