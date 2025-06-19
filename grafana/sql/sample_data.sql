-- Sample data for demonstration purposes
-- This file is automatically loaded during PostgreSQL initialization

SELECT log_message('INFO', 'Loading sample data...');

-- Sample connections data
INSERT INTO connections (time, hostname, source_address, destination_address, source_port, destination_port, protocol, direction, packets, bytes, duration_ms, process_name) VALUES
(NOW() - INTERVAL '1 hour', 'test-host', '192.168.1.100', '8.8.8.8', 54321, 53, 'udp', 'outgoing', 10, 520, 1000, 'systemd-resolved'),
(NOW() - INTERVAL '1 hour', 'test-host', '192.168.1.100', '142.250.191.78', 45678, 443, 'tcp', 'outgoing', 25, 3500, 5000, 'chrome'),
(NOW() - INTERVAL '1 hour', 'test-host', '192.168.1.100', '40.112.72.205', 34567, 443, 'tcp', 'outgoing', 30, 4200, 6000, 'teams'),
(NOW() - INTERVAL '30 minutes', 'test-host', '192.168.1.100', '8.8.8.8', 54322, 53, 'udp', 'outgoing', 15, 780, 1500, 'systemd-resolved'),
(NOW() - INTERVAL '30 minutes', 'test-host', '192.168.1.100', '142.250.191.78', 45679, 443, 'tcp', 'outgoing', 40, 5600, 8000, 'chrome'),
(NOW() - INTERVAL '15 minutes', 'test-host', '192.168.1.100', '157.240.12.35', 23456, 443, 'tcp', 'outgoing', 20, 2800, 4000, 'firefox');

-- Sample protocol stats
INSERT INTO protocol_stats (time, hostname, protocol, connections, packets, bytes) VALUES
(NOW() - INTERVAL '1 hour', 'test-host', 'tcp', 3, 95, 13300),
(NOW() - INTERVAL '1 hour', 'test-host', 'udp', 1, 10, 520),
(NOW() - INTERVAL '30 minutes', 'test-host', 'tcp', 2, 60, 8400),
(NOW() - INTERVAL '30 minutes', 'test-host', 'udp', 1, 15, 780),
(NOW() - INTERVAL '15 minutes', 'test-host', 'tcp', 1, 20, 2800);

-- Sample top destinations
INSERT INTO top_destinations (time, hostname, destination_address, rank, connections, packets, bytes) VALUES
(NOW() - INTERVAL '1 hour', 'test-host', '142.250.191.78', 1, 2, 65, 9100),
(NOW() - INTERVAL '1 hour', 'test-host', '40.112.72.205', 2, 1, 30, 4200),
(NOW() - INTERVAL '1 hour', 'test-host', '8.8.8.8', 3, 1, 10, 520),
(NOW() - INTERVAL '30 minutes', 'test-host', '142.250.191.78', 1, 1, 40, 5600),
(NOW() - INTERVAL '30 minutes', 'test-host', '8.8.8.8', 2, 1, 15, 780),
(NOW() - INTERVAL '15 minutes', 'test-host', '157.240.12.35', 1, 1, 20, 2800);

-- Sample process stats
INSERT INTO process_stats (time, hostname, process_name, rank, connections, packets, bytes) VALUES
(NOW() - INTERVAL '1 hour', 'test-host', 'chrome', 1, 2, 65, 9100),
(NOW() - INTERVAL '1 hour', 'test-host', 'teams', 2, 1, 30, 4200),
(NOW() - INTERVAL '1 hour', 'test-host', 'systemd-resolved', 3, 1, 10, 520),
(NOW() - INTERVAL '30 minutes', 'test-host', 'chrome', 1, 1, 40, 5600),
(NOW() - INTERVAL '30 minutes', 'test-host', 'systemd-resolved', 2, 1, 15, 780),
(NOW() - INTERVAL '15 minutes', 'test-host', 'firefox', 1, 1, 20, 2800);

-- Sample system metrics
INSERT INTO system_metrics (time, hostname, total_connections, total_packets, total_bytes, unique_destinations, unique_processes, cpu_usage, memory_usage) VALUES
(NOW() - INTERVAL '1 hour', 'test-host', 4, 105, 13820, 3, 3, 45.2, 67.8),
(NOW() - INTERVAL '30 minutes', 'test-host', 3, 75, 9180, 2, 2, 38.5, 63.2),
(NOW() - INTERVAL '15 minutes', 'test-host', 1, 20, 2800, 1, 1, 25.1, 58.9);

SELECT log_message('INFO', 'Sample data loaded successfully');

-- Refresh materialized views with sample data
REFRESH MATERIALIZED VIEW hourly_connection_summary;

SELECT log_message('INFO', 'Materialized views refreshed'); 