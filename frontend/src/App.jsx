import { useState, useEffect } from 'react'
import './App.css'

const API_BASE = '/api'

function App() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [history, setHistory] = useState([])
  const [selectedFeatures, setSelectedFeatures] = useState(null)
  const [error, setError] = useState('')
  const [showFeatures, setShowFeatures] = useState(false)

  useEffect(() => {
    fetchHistory()
  }, [])

  const fetchHistory = async () => {
    try {
      const res = await fetch(`${API_BASE}/history?limit=50`)
      const data = await res.json()
      setHistory(data.scans || [])
    } catch (err) {
      console.error('Failed to fetch history:', err)
    }
  }

  const handleScan = async () => {
    if (!url.trim()) {
      setError('Please enter a URL')
      return
    }
    
    let processedUrl = url.trim()
    if (!processedUrl.match(/^https?:\/\//i)) {
      processedUrl = 'https://' + processedUrl
    }
    const urlObj = new URL(processedUrl)
    if (!urlObj.hostname.startsWith('www.')) {
      urlObj.hostname = 'www.' + urlObj.hostname
    }
    processedUrl = urlObj.toString()
    
    setError('')
    setLoading(true)
    try {
      const res = await fetch(`${API_BASE}/predict`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: processedUrl })
      })
      const data = await res.json()
      if (res.ok) {
        setHistory(prev => [data, ...prev])
        setUrl(processedUrl)
      } else {
        setError(data.detail || 'Prediction failed')
      }
    } catch (err) {
      setError('Failed to connect to server')
    }
    setLoading(false)
  }

  const handleViewDetails = async (urlToScan) => {
    try {
      const res = await fetch(`${API_BASE}/features`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlToScan })
      })
      const data = await res.json()
      setSelectedFeatures(data)
      setShowFeatures(true)
    } catch (err) {
      setError('Failed to fetch features')
    }
  }

  const handleDelete = async (urlToDelete) => {
    try {
      const res = await fetch(`${API_BASE}/history/delete?url=${encodeURIComponent(urlToDelete)}`, {
        method: 'DELETE'
      })
      if (res.ok) {
        setHistory(prev => prev.filter(h => h.original_url !== urlToDelete))
      } else {
        const data = await res.json()
        setError(data.detail || 'Failed to delete URL')
      }
    } catch (err) {
      setError('Failed to delete URL')
    }
  }

  return (
    <div className="app">
      <header className="header">
        <div className="logo">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <span>PhishGuard</span>
        </div>
        <p className="tagline">Advanced Phishing URL Detection System</p>
      </header>

      <main className="main">
        <section className="hero-section">
          <h1>Check if a URL is Safe</h1>
          <p>Enter a URL below to scan it for potential phishing threats using our AI-powered detection system.</p>
          
          <div className="search-box">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL (e.g., https://example.com)"
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              disabled={loading}
            />
            <button onClick={handleScan} disabled={loading} className="scan-btn">
              {loading ? (
                <span className="spinner"></span>
              ) : (
                <>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="11" cy="11" r="8"/>
                    <path d="M21 21l-4.35-4.35"/>
                  </svg>
                  Scan URL
                </>
              )}
            </button>
          </div>
          {error && <p className="error-msg">{error}</p>}
        </section>

        <section className="results-section">
          <h2>Scan History</h2>
          {history.length === 0 ? (
            <p className="no-data">No URLs scanned yet. Enter a URL above to get started.</p>
          ) : (
            <div className="results-table">
              <div className="table-header">
                <span>URL</span>
                <span>Status</span>
                <span>Phishing Score</span>
                <span>Actions</span>
              </div>
              {history.map((item, idx) => (
                <div key={idx} className="table-row">
                  <span className="url-cell" title={item.original_url}>
                    {item.original_url}
                  </span>
                  <span className={`status ${item.is_phishing ? 'phishing' : 'safe'}`}>
                    {item.is_phishing ? '⚠ Phishing' : '✓ Safe'}
                  </span>
                  <span className={`score ${item.is_phishing ? 'danger' : 'success'}`}>
                    {item.phishing_rate}%
                  </span>
                  <span className="actions">
                    <button className="view-btn" onClick={() => handleViewDetails(item.original_url)}>
                      View Details
                    </button>
                    <button className="delete-btn" onClick={() => handleDelete(item.original_url)}>
                      Delete
                    </button>
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>
      </main>

      {showFeatures && selectedFeatures && (
        <div className="modal-overlay" onClick={() => setShowFeatures(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>URL Features Analysis</h3>
              <button className="close-btn" onClick={() => setShowFeatures(false)}>×</button>
            </div>
            <div className="modal-content">
              <p className="feature-url"><strong>URL:</strong> {selectedFeatures.original_url}</p>
              <div className="features-grid">
                {Object.entries(selectedFeatures.features).map(([key, value]) => (
                  <div key={key} className="feature-item">
                    <span className="feature-name">{key.replace(/_/g, ' ')}</span>
                    <span className="feature-value">{value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      <footer className="footer">
        <p>© 2026 PhishGuard - Phishing URL Detection System</p>
      </footer>
    </div>
  )
}

export default App