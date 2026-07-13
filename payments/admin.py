from django.conf import settings
from django.contrib import admin, messages
from django.core.mail import send_mail

from .models import Payment


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ('user', 'provider', 'amount', 'currency', 'status', 'provider_transaction_id', 'created_at')
    list_filter = ('provider', 'status', 'created_at')
    search_fields = ('user__username', 'user__email', 'provider_transaction_id')
    readonly_fields = ('id', 'created_at')
    actions = ['approve_upi_payments']

    @admin.action(description="Approve selected UPI payments (activates subscription + emails user)")
    def approve_upi_payments(self, request, queryset):
        from subscriptions.models import Plan, Subscription

        approved = 0
        skipped = 0

        for payment in queryset:
            if payment.provider != Payment.Provider.UPI or payment.status == Payment.Status.SUCCEEDED:
                skipped += 1
                continue

            plan_id = (payment.raw_payload or {}).get('plan_id')
            plan = Plan.objects.filter(id=plan_id).first() if plan_id else None
            if plan is None:
                skipped += 1
                continue

            # Deactivate any existing active subscription, then activate the new one.
            Subscription.objects.filter(user=payment.user, status=Subscription.Status.ACTIVE).update(
                status=Subscription.Status.CANCELED
            )
            Subscription.objects.create(
                user=payment.user,
                plan=plan,
                status=Subscription.Status.ACTIVE,
                provider='upi',
                provider_subscription_id=str(payment.id),
            )

            payment.status = Payment.Status.SUCCEEDED
            payment.save(update_fields=['status'])

            if payment.user.email:
                try:
                    send_mail(
                        subject='Your Fora AI Pro plan is now active!',
                        message=(
                            f'Hi {payment.user.get_full_name() or payment.user.username},\n\n'
                            f'Your payment for {plan.name} has been verified and unlimited scans '
                            f'are now active on your account.\n\n'
                            f'Happy scanning!\nFora AI'
                        ),
                        from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', None),
                        recipient_list=[payment.user.email],
                        fail_silently=True,
                    )
                except Exception:
                    pass

            approved += 1

        if approved:
            self.message_user(request, f'{approved} payment(s) approved and subscriptions activated.', messages.SUCCESS)
        if skipped:
            self.message_user(request, f'{skipped} payment(s) skipped (not pending UPI, or plan missing).', messages.WARNING)
