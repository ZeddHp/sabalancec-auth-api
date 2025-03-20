function getExpiryTime(duration) {
    const now = Date.now(); // Current time in milliseconds
    const match = duration.match(/(\d+)([smhd])/); // Extract number and unit

    if (!match) throw new Error("Invalid duration format");

    const value = parseInt(match[1], 10);
    const unit = match[2];

    let multiplier;

    switch (unit) {
        case 's': multiplier = 1000; break;          // Seconds to milliseconds
        case 'm': multiplier = 60 * 1000; break;     // Minutes to milliseconds
        case 'h': multiplier = 60 * 60 * 1000; break;// Hours to milliseconds
        case 'd': multiplier = 24 * 60 * 60 * 1000; break; // Days to milliseconds
        default: throw new Error("Unsupported time unit");
    }

    return Math.floor((now + value * multiplier) / 1000); // Convert to Unix time (seconds)
}

module.exports = { getExpiryTime} ;