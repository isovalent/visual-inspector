# Visual Inspector

A comprehensive web-based tool for inspecting and debugging Cilium network policies in Kubernetes clusters. Visual Inspector provides an intuitive interface to visualize policy paths, test connectivity, capture packets, and trace network flows.

## Overview

Visual Inspector helps you understand and troubleshoot Cilium network policies by providing:
- Real-time policy inspection and visualization
- Interactive policy path analysis between endpoints
- Connectivity testing with live policy counter updates
- Packet capture integration (tcpdump)
- Kernel-level packet tracing (pwru)
- Policy selector analysis

## Current Features

### Policy Management
- **Show Policies**: Display all Cilium policies across all endpoints with live updates
- **Policy Path**: Analyze the complete policy path between source and destination endpoints
  - View Egress policies from source
  - View Ingress policies to destination
  - See reserved labels (host, world, health, etc.) with identity numbers
  - Display opposite endpoint as `namespace/class` with traffic statistics
  - Highlight policy changes in real-time with green background
- **Policy Counters Live**: Auto-refresh policy data every 5 seconds to track changes
- **Endpoints Without Policy**: Identify endpoints that have no policies applied

### Connectivity Testing
- **Test Policy**: Run connectivity tests between endpoints
  - Automatic protocol and port detection from destination pod
  - Custom protocol (TCP/UDP) and port selection
  - Highlight matching policy rows based on test results
  - Show before/after policy counters
- **Policy Test Results**: Display success/failure of connectivity tests with detailed output

### Packet Analysis
- **Packet Capture**: Run tcpdump on source and destination pods
  - Capture packets for 60 seconds
  - Filter by protocol and port
  - Display full tcpdump command used
  - Stop capture early and retrieve partial results
- **pwru Integration**: Kernel-level packet tracing
  - Traces packets through Linux kernel functions
  - Shows packet flow with tuple information
  - Automatically starts before connectivity tests
  - Captures up to 200 events with 15-second timeout

### Endpoint Management
- **Endpoint List**: View all Cilium endpoints with details
  - Pod name, namespace, IP address
  - Endpoint ID and security identity
  - Labels and metadata
- **Endpoint Index**: Browse endpoints by pod for policy path analysis
  - Sorted with named pods first, unnamed at bottom
  - Quick selection for source and destination

### Policy Selectors
- **Show Selectors**: Display policy selectors and their matching endpoints
- **Relevant Policies**: Show policies that apply to specific endpoint pairs

## Application Features

### Runner Script Commands

```bash
./run.sh install   # Install npm dependencies
./run.sh start     # Start both backend and frontend servers (default)
./run.sh stop      # Stop all running processes
./run.sh restart   # Restart the application (useful after code changes)
./run.sh status    # Check if the application is running
./run.sh logs      # Tail both server logs in real-time
```

### Runner Script Features

- **Kubeconfig Support**: Reads `KUBECONFIG_PATH` environment variable (defaults to `~/.kube/config`)
- **Process Management**: Stores PIDs in files and properly kills processes on stop/restart
- **Auto-install**: Checks if dependencies are installed and runs `npm install` if needed
- **Colored Output**: Uses colors for better readability (info, success, warn, error)
- **Log Files**: Redirects output to `server.log` and `dev.log` for debugging
- **Graceful Shutdown**: Tries SIGTERM first, then SIGKILL if needed

## Prerequisites

- Node.js (v16 or later)
- npm
- kubectl configured with access to your Kubernetes cluster
- Cilium installed in the cluster
- (Optional) pwru-enabled debug container image for kernel tracing: `quay.io/isovalent-dev/cilium-debug-toolbox:latest`

## Installation

1. Clone the repository or navigate to the visual-inspector directory:
   ```bash
   cd tools/visual-inspector
   ```

2. Install dependencies:
   ```bash
   ./run.sh install
   ```

## Usage

### Starting the Application

Basic start:
```bash
./run.sh start
```

With custom kubeconfig:
```bash
KUBECONFIG_PATH=/path/to/kubeconfig ./run.sh start
```

The application will be available at: **http://localhost:5174**

### After Code Changes

Restart the application to apply changes:
```bash
./run.sh restart
```

### Viewing Logs

Monitor application logs in real-time:
```bash
./run.sh logs
```

Or view individual log files:
```bash
tail -f server.log  # Backend logs
tail -f dev.log     # Frontend logs
```

### Stopping the Application

```bash
./run.sh stop
```

## Application Workflow

### 1. Load Kubeconfig
- Upload your kubeconfig file via the UI, or
- Set `KUBECONFIG_PATH` environment variable before starting

### 2. Inspect Policies
- Click **Show Policies** to view all policies
- Enable **Policy Counters Live** for real-time updates
- Use **Endpoints Without Policy** to find unprotected endpoints

### 3. Analyze Policy Path
- Click **Policy Path** to open the endpoint selector
- Choose source and destination endpoints
- Click **Run** to see the complete policy path
- View Egress policies from source and Ingress policies to destination

### 4. Test Connectivity
- In Policy Path view, select protocol and port (or use auto-detected values)
- Click **Test Policy** to run connectivity tests
- View test results and pwru packet traces
- Matching policy rows are highlighted in yellow

### 5. Capture Packets
- Click **Packet Capture** on source or destination
- Packets are captured for 60 seconds
- Click **Stop Capture** to retrieve partial results
- View tcpdump output with full command line

## Architecture

### Backend (Node.js/Express)
- REST API server running on port 3000
- Executes kubectl commands to interact with Cilium
- Manages temporary kubeconfig files per session
- Handles packet capture and pwru execution

### Frontend (React/Vite)
- Modern React application with Tailwind CSS
- Real-time updates with auto-refresh
- Interactive policy visualization
- Responsive design for large datasets

## API Endpoints

- `POST /api/kubeconfig` - Upload kubeconfig
- `GET /api/endpoints` - List all endpoints
- `GET /api/policies` - Show all policies
- `GET /api/ep-policies` - Show policies per endpoint
- `GET /api/ep-no-policy` - List endpoints without policies
- `GET /api/selectors` - Show policy selectors
- `GET /api/ep-index` - Get endpoint index for policy path
- `GET /api/policy-path` - Analyze policy path between endpoints
- `POST /api/policy-test` - Test connectivity between endpoints
- `POST /api/tcpdump` - Start packet capture
- `POST /api/tcpdump/stop` - Stop packet capture
- `POST /api/pwru` - Run pwru packet tracing

## Configuration

### Environment Variables

- `KUBECONFIG_PATH` - Path to kubeconfig file (default: `~/.kube/config`)
- `PORT` - Backend server port (default: 3000)

### Session Management

- Sessions are managed server-side with express-session
- Each session stores its own kubeconfig
- Default kubeconfig is auto-loaded if available

## Troubleshooting

### No Cilium Pods Found
- Ensure Cilium is installed in the `kube-system` namespace
- Check that your kubeconfig has proper permissions
- Verify kubectl can access the cluster: `kubectl get pods -n kube-system -l k8s-app=cilium`

### Packet Capture Not Working
- Ensure the debug container image supports tcpdump
- Check pod security policies allow ephemeral containers
- Verify network policies don't block the capture

### pwru Not Capturing Packets
- Ensure the debug toolbox image is available: `quay.io/isovalent-dev/cilium-debug-toolbox:latest`
- Check that pwru has proper permissions (sysadmin profile)
- Verify the filter matches the actual traffic (check IPs and ports)
- Increase capture duration if traffic is intermittent

### Policy Path Shows No Data
- Verify both source and destination endpoints exist
- Check that endpoints have associated pods
- Ensure Cilium is properly managing the endpoints

## Development

### Project Structure

```
visual-inspector/
├── server.js              # Backend Express server
├── src/
│   └── App.jsx           # Frontend React application
├── package.json          # Dependencies and scripts
├── vite.config.js        # Vite configuration
├── run.sh                # Runner script
├── server.log            # Backend logs (generated)
├── dev.log               # Frontend logs (generated)
└── README.md             # This file
```

### Making Changes

1. Edit the code (server.js or src/App.jsx)
2. Restart the application:
   ```bash
   ./run.sh restart
   ```
3. The changes will be applied immediately

### Adding New Features

- Backend: Add new routes in `server.js`
- Frontend: Add new components or modify `App.jsx`
- Both servers support hot reload during development

## Contributing

When contributing, please:
1. Test your changes with `./run.sh restart`
2. Verify all features work correctly
3. Update this README if adding new features
4. Check logs for errors: `./run.sh logs`

## License

Apache 2.0

## Support

For issues or questions:
- Check the logs: `./run.sh logs`
- Verify Cilium installation: `cilium status`
- Test kubectl access: `kubectl get pods -n kube-system`

## Acknowledgments

- Built with React, Vite, Tailwind CSS, and Express
- Integrates with Cilium for network policy management
- Uses pwru for kernel-level packet tracing
- Leverages kubectl for Kubernetes cluster interaction
- https://github.com/isovalent/cilium-debug-toolbox
