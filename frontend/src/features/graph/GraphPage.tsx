import { useNavigate } from 'react-router-dom'
import { Network } from 'lucide-react'
import { Button } from '@/components/ui/Button'

export function GraphPage() {
  const navigate = useNavigate()

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">Graph Analysis</h1>
        <p className="text-sm text-text-muted mt-1">Visualize attack paths and entity relationships</p>
      </div>

      <div style={{ textAlign: 'center', padding: '80px 20px' }}>
        <Network size={48} style={{ color: '#3A4150', marginBottom: 16, display: 'block', margin: '0 auto 16px' }} />
        <h2 style={{ fontSize: 16, color: '#5C6373', marginBottom: 8, fontWeight: 600 }}>
          Investigation Graph
        </h2>
        <p style={{ fontSize: 13, color: '#3A4150', marginBottom: 24 }}>
          Open an investigation to view its attack graph
        </p>
        <Button variant="primary" onClick={() => navigate('/investigations')}>
          Go to Investigations
        </Button>
      </div>
    </div>
  )
}
