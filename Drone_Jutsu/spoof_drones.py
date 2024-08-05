import random
import time
import math

def adjust_coordinates_within_radius(center_lat, center_lon, lat, lon, max_radius_deg, max_movement_deg):
    """
    Adjust the coordinates by a small random value between -max_movement_deg and +max_movement_deg degrees,
    ensuring they stay within the max_radius_deg from the center point and do not exceed max_movement_deg.
    """
    while True:
        delta_lat = random.uniform(-max_movement_deg, max_movement_deg)
        delta_lon = random.uniform(-max_movement_deg, max_movement_deg)
        new_lat = lat + delta_lat
        new_lon = lon + delta_lon

        # Calculate the distance from the center
        distance = math.sqrt((new_lat - center_lat)**2 + (new_lon - center_lon)**2)
        if distance <= max_radius_deg:
            # Ensure the movement does not exceed max_movement_deg
            movement = math.sqrt(delta_lat**2 + delta_lon**2)
            if movement <= max_movement_deg:
                return new_lat, new_lon

# Example central coordinates (latitude, longitude)
center_lat = 47.3763399
center_lon = 8.5312562
max_radius_deg = 0.58  # Maximum radius in degrees (approx 40 miles)
max_movement_deg = 0.0042  # Maximum movement per update (approx 5 mph over 3 seconds)
update_interval = 3  # Time in seconds between updates

# Number of drones to spoof
m = 5  # Example value, adjust as needed

# Initial positions for the drones
drones = [(center_lat, center_lon) for _ in range(m)]

while True:
    for i in range(m):
        lat, lon = drones[i]
        new_lat, new_lon = adjust_coordinates_within_radius(center_lat, center_lon, lat, lon, max_radius_deg, max_movement_deg)
        drones[i] = (new_lat, new_lon)
        # Use these new_lat and new_lon values to set the drone's position
        print(f"Drone {i+1}: Lat {new_lat}, Lon {new_lon}")
        # Insert code here to broadcast the spoofed coordinates
        
        # Example of how you might broadcast the coordinates
        # broadcast_coordinates(interface, new_lat, new_lon)
    
    # Wait for the specified update interval before updating again
    time.sleep(update_interval)
