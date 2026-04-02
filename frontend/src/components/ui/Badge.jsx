import React from 'react';
import PropTypes from 'prop-types';
import './Badge.css'; // Assuming you will style the badge

const Badge = ({ severity, children }) => {
  const severityClass = `badge badge--${severity}`;

  return (
    <span className={severityClass}>
      {children}
    </span>
  );
};

Badge.propTypes = {
  severity: PropTypes.oneOf(['low', 'medium', 'high']).isRequired,
  children: PropTypes.node.isRequired,
};

export default Badge;