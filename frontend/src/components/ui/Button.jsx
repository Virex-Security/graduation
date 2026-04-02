import React from 'react';
import PropTypes from 'prop-types';

const Button = ({ variant, children, onClick }) => {
    const baseStyle = 'px-4 py-2 rounded';
    const variantStyles = {
        primary: 'bg-blue-500 text-white',
        secondary: 'bg-gray-500 text-white',
        danger: 'bg-red-500 text-white',
    };

    return (
        <button className={`${baseStyle} ${variantStyles[variant]}`} onClick={onClick}>
            {children}
        </button>
    );
};

Button.propTypes = {
    variant: PropTypes.oneOf(['primary', 'secondary', 'danger']).isRequired,
    children: PropTypes.node.isRequired,
    onClick: PropTypes.func,
};

export default Button;