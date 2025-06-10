import math

class RoboticArmSegment:
    def __init__(self, length, angle=0):
        self.length = length
        self.angle = angle 

    def get_end_pos(self, start_x, start_y):
        rad_angle = math.radians(self.angle)
        end_x = start_x + self.length * math.cos(rad_angle)
        end_y = start_y - self.length * math.sin(rad_angle)
        return end_x, end_y