import { memo } from 'react';
import { CheckIcon, XMarkIcon } from '@heroicons/react/24/outline';
import { SecondaryButton } from '../components/Buttons';
import { useAuth } from '../utils/useAuth';
import { useToast } from '../utils/useToast';

function PriceCard({ name, price, features, mostPopular, current, onUpgrade, highlightColor = 'brand-primary' }) {
  return (
    <div className={`relative flex flex-col p-8 rounded-3xl border transition-all duration-300 hover:-translate-y-2 hover:shadow-2xl hover:bg-bg-card/50 ${
      mostPopular 
        ? `border-${highlightColor} bg-brand-primary/5 shadow-lg shadow-brand-primary/10` 
        : 'border-border-dim/50 bg-bg-card/30'
    }`}>
      {mostPopular && (
        <div className="absolute top-0 right-0 overflow-hidden rounded-tr-3xl w-24 h-24 pointer-events-none">
          <div className="absolute top-ds-4 right-[-24px] rotate-45 bg-brand-primary text-white text-ds-micro font-black py-ds-1 px-ds-8 uppercase tracking-ds-wider">
            Best Value
          </div>
        </div>
      )}

      <div className="mb-8">
        <h3 className="text-xl font-bold text-text-primary mb-2 normal-case tracking-normal">{name}</h3>
        <div className="flex items-baseline gap-1">
          <span className="text-4xl font-black text-text-primary normal-case tracking-normal">${price}</span>
          <span className="text-sm text-text-muted">/month</span>
        </div>
      </div>

      <ul className="flex-1 space-y-4 mb-8">
        {features.map((f, i) => (
          <li key={i} className={`flex items-center gap-3 text-sm ${f.included ? 'text-text-secondary' : 'text-text-muted opacity-50'}`}>
            {f.included ? (
              <CheckIcon className="w-5 h-5 text-brand-primary flex-shrink-0" />
            ) : (
              <XMarkIcon className="w-5 h-5 text-text-muted flex-shrink-0" />
            )}
            <span>{f.text}</span>
          </li>
        ))}
      </ul>

      {current ? (
        <div className="text-center p-3 rounded-xl bg-bg-secondary text-text-muted text-xs font-bold uppercase tracking-widest">
          Your Current Plan
        </div>
      ) : (
        <SecondaryButton 
          onClick={onUpgrade} 
          className={`w-full py-3 ${mostPopular ? 'bg-brand-primary text-white border-transparent hover:bg-brand-secondary' : ''}`}
        >
          {price === 0 ? 'Downgrade' : mostPopular ? 'Upgrade to Pro' : 'Choose Plan'}
        </SecondaryButton>
      )}
    </div>
  );
}

export default memo(function PricingPage() {
  const { user } = useAuth();
  const { addToast } = useToast();

  const handleUpgrade = (plan) => {
    addToast(`Reducting to checkout for ${plan}...`, 'success');
    // Mock checkout or API call
  };

  const plans = [
    {
      name: 'Free',
      price: 0,
      current: user?.subscription === 'Free',
      features: [
        { text: 'Basic Dashboard', included: true },
        { text: 'Real-time Alerts', included: true },
        { text: '24h Threat History', included: true },
        { text: 'AI Model Insights', included: false },
        { text: 'Custom PDF Reports', included: false },
        { text: 'Priority Support', included: false },
      ]
    },
    {
      name: 'Pro',
      price: 29,
      mostPopular: true,
      current: user?.subscription === 'Pro',
      features: [
        { text: 'Everything in Free', included: true },
        { text: '30-Day History', included: true },
        { text: 'Advanced ML Analysis', included: true },
        { text: 'Custom PDF Reports', included: true },
        { text: 'API Access', included: true },
        { text: 'Priority Support', included: false },
      ]
    },
    {
      name: 'Enterprise',
      price: 99,
      current: user?.subscription === 'Enterprise',
      features: [
        { text: 'Everything in Pro', included: true },
        { text: 'Unlimited History', included: true },
        { text: 'Dedicated AI Training', included: true },
        { text: 'Multi-node Monitoring', included: true },
        { text: '24/7 Priority Support', included: true },
        { text: 'Dedicated Account Manager', included: true },
      ]
    }
  ];

  return (
    <div className="py-12 max-w-6xl mx-auto px-4">
      <div className="text-center max-w-2xl mx-auto mb-16">
        <h1 className="text-4xl sm:text-5xl font-black text-text-primary mb-4 leading-tight normal-case tracking-normal">
          Supercharge Your <span className="text-brand-primary">Security</span>
        </h1>
        <p className="text-lg text-text-secondary leading-relaxed">
          Scale your threat intelligence with advanced ML capabilities and unlimited forensic history.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
        {plans.map((p, i) => (
          <PriceCard key={i} {...p} onUpgrade={() => handleUpgrade(p.name)} />
        ))}
      </div>

      {/* Comparisons / Social Proof */}
      <div className="mt-24 grid grid-cols-1 sm:grid-cols-3 gap-8 text-center bg-bg-card/20 rounded-3xl p-12 border border-border-dim/50">
        <div className="space-y-2">
          <div className="text-3xl font-black text-brand-primary">12ms</div>
          <div className="text-xs text-text-muted uppercase font-bold tracking-widest">Global Latency</div>
        </div>
        <div className="space-y-2">
          <div className="text-3xl font-black text-brand-secondary">99.9%</div>
          <div className="text-xs text-text-muted uppercase font-bold tracking-widest">Model Accuracy</div>
        </div>
        <div className="space-y-2">
          <div className="text-3xl font-black text-info">24/7</div>
          <div className="text-xs text-text-muted uppercase font-bold tracking-widest">SOC Monitoring</div>
        </div>
      </div>
    </div>
  );
});
