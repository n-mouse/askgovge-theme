# -*- encoding : utf-8 -*-
# Add a callback - to be executed before each request in development,
# and at startup in production - to patch existing app classes.
# Doing so in init/environment.rb wouldn't work in development, since
# classes are reloaded, but initialization is not run each time.
# See http://stackoverflow.com/questions/7072758/plugin-not-reloading-in-development-mode
#
Rails.configuration.to_prepare do

  RequestController.class_eval do
    def new
		# All new requests are of normal_sort
		if !params[:outgoing_message].nil?
		  params[:outgoing_message][:what_doing] = 'normal_sort'
		end

		# If we've just got here (so no writing to lose), and we're already
		# logged in, force the user to describe any undescribed requests. Allow
		# margin of 1 undescribed so it isn't too annoying - the function
		# get_undescribed_requests also allows one day since the response
		# arrived.
		if !@user.nil? && params[:submitted_new_request].nil?
		  @undescribed_requests = @user.get_undescribed_requests
		  if @undescribed_requests.size > 1
			render :action => 'new_please_describe'
			return
		  end
		end

		# Banned from making new requests?
		user_exceeded_limit = false
		if !authenticated_user.nil? && !authenticated_user.can_file_requests?
		  # If the reason the user cannot make new requests is that they are
		  # rate-limited, it’s possible they composed a request before they
		  # logged in and we want to include the text of the request so they
		  # can squirrel it away for tomorrow, so we detect this later after
		  # we have constructed the InfoRequest.
		  user_exceeded_limit = authenticated_user.exceeded_limit?
		  if !user_exceeded_limit
			@details = authenticated_user.can_fail_html
			render :template => 'user/banned'
			return
		  end
		  # User did exceed limit
		  @next_request_permitted_at = authenticated_user.next_request_permitted_at
		end

		# First time we get to the page, just display it
		if params[:submitted_new_request].nil? || params[:reedit]
		  if user_exceeded_limit
			render :template => 'user/rate_limited'
			return
		  end
		  return render_new_compose(batch=false)
		end

		# CREATE ACTION

		# Check we have :public_body_id - spammers seem to be using :public_body
		# erroneously instead
		if params[:info_request][:public_body_id].blank?
		  redirect_to frontpage_path and return
		end

		# See if the exact same request has already been submitted
		# TODO: this check should theoretically be a validation rule in the
		# model, except we really want to pass @existing_request to the view so
		# it can link to it.
		@existing_request = InfoRequest.find_existing(params[:info_request][:title], params[:info_request][:public_body_id], params[:outgoing_message][:body])

		# Create both FOI request and the first request message
		@info_request = InfoRequest.create_from_attributes(info_request_params,
														   outgoing_message_params)
		@outgoing_message = @info_request.outgoing_messages.first

		# Maybe we lost the address while they're writing it
		unless @info_request.public_body.is_requestable?
		  render :action => "new_#{ @info_request.public_body.not_requestable_reason }"
		  return
		end

		# See if values were valid or not
		if @existing_request || !@info_request.valid?
		  # We don't want the error "Outgoing messages is invalid", as in this
		  # case the list of errors will also contain a more specific error
		  # describing the reason it is invalid.
		  @info_request.errors.delete(:outgoing_messages)

		  render :action => 'new'
		  return
		end

		# Show preview page, if it is a preview
		if params[:preview].to_i == 1
		  return render_new_preview
		end

		if user_exceeded_limit
		  render :template => 'user/rate_limited'
		  return
		end

		if !authenticated?(
			:web => _("To send and publish your FOI request").to_str,
			:email => _("Then your FOI request to {{public_body_name}} will be sent and published.",:public_body_name=>@info_request.public_body.name),
			:email_subject => _("Confirm your FOI request to {{public_body_name}}",:public_body_name=>@info_request.public_body.name)
		  )
		  # do nothing - as "authenticated?" has done the redirect to signin page for us
		  return
		end

		@info_request.user = request_user

		if spam_subject?(@outgoing_message.subject, @user)
		  handle_spam_subject(@info_request.user) && return
		end

		if blocked_ip?(country_from_ip, @user)
		  handle_blocked_ip(@info_request) && return
		end

		if AlaveteliConfiguration.new_request_recaptcha && !@user.confirmed_not_spam?
		  if @render_recaptcha && !verify_recaptcha
			flash.now[:error] = _('There was an error with the reCAPTCHA. ' \
								  'Please try again.')

			if send_exception_notifications?
			  e = Exception.new("Possible blocked non-spam (recaptcha) from #{@info_request.user_id}: #{@info_request.title}")
			  ExceptionNotifier.notify_exception(e, :env => request.env)
			end

			render :action => 'new'
			return
		  end
		end

		# This automatically saves dependent objects, such as @outgoing_message, in the same transaction
		@info_request.save!
		
		signum = false
		
		if @user && @user.is_admin? && @user.name=="Signature Testing User"
		  request_address = "<p><strong>Address</strong>: "+helpers.sanitize(params[:outgoing_message][:address],tags:[], attributes:[])+"</p>" || ""
		  request_phone = "<p><strong>Phone</strong>: "+helpers.sanitize(params[:outgoing_message][:phone],tags:[], attributes:[])+"</p>" || ""
		  request_idnumber = "<p><strong>ID number</strong>: "+helpers.sanitize(params[:outgoing_message][:idnumber],tags:[], attributes:[])+"</p>" || ""
		  if params[:outgoing_message][:signature]
		    signum = @info_request.id.to_s+"-"+SecureRandom.hex(10).to_s;
		    request_uri = URI::Data.new(params[:outgoing_message][:signature])
		    request_text = helpers.sanitize(helpers.simple_format(params[:outgoing_message][:body]),tags:['br','p'])
		    request_html = "<!DOCTYPE html><html><head><title>Info request</title></head><body>#{request_text}<br>
		    #{request_address}#{request_phone}#{request_idnumber}
		    <p><img src='#{request_uri}'/></p></body></html>"
		    request_kit = PDFKit.new(request_html, :page_size => 'Letter', :disable_local_file_access => true, :disable_javascript => true)
		    request_file = request_kit.to_file("tmp/pdf/pdf-#{signum}.pdf")
		  end
		end

		if @outgoing_message.sendable?
		  begin
			mail_message = OutgoingMailer.initial_request(
			  @outgoing_message.info_request,
			  @outgoing_message,
			  signum
			).deliver_now
		  rescue *OutgoingMessage.expected_send_errors => e
			# Catch a wide variety of potential ActionMailer failures and
			# record the exception reason so administrators don't have to
			# dig into logs.
			@outgoing_message.record_email_failure(
			  e.message
			)

			flash[:error] = _("An error occurred while sending your request to " \
							  "{{authority_name}} but has been saved and flagged " \
							  "for administrator attention.",
							  authority_name: @info_request.public_body.name)
		  else
			@outgoing_message.record_email_delivery(
			  mail_message.to_addrs.join(', '),
			  mail_message.message_id
			)

			flash[:request_sent] = true
		  ensure
			# Ensure the InfoRequest is fully updated before templating to
			# isolate templating issues recording delivery status.
			@info_request.save!
		  end
		end

		redirect_to show_request_path(:url_title => @info_request.url_title)
	  end

  end

  UserController.class_eval do 
	def signup
		# Make the user and try to save it
		@user_signup = User.new(user_params(:user_signup))
		error = false
		if @request_from_foreign_country && !verify_recaptcha
		  flash.now[:error] = _('There was an error with the reCAPTCHA. ' \
								  'Please try again.')
		  error = true
		end
		if params[:name_public_ok] != "1" 
			flash.now[:error] = _("You have to agree to processing of your personal data, otherwise we won't be able to create your account")
			error = true
		end
		@user_signup.valid?
		user_alreadyexists = User.find_user_by_email(params[:user_signup][:email])
		if user_alreadyexists
		  # attempt to remove the 'already in use message' from the errors hash
		  # so it doesn't get accidentally shown to the end user
		  @user_signup.errors[:email].delete_if { |message| message == _("This email is already in use") }
		end
		if error || !@user_signup.errors.empty?
		  # Show the form
		  render :action => 'sign'
		else
		  if user_alreadyexists
			already_registered_mail user_alreadyexists
			return
		  else
			# New unconfirmed user
	
			# Rate limit signups
			ip_rate_limiter.record(user_ip)
	
			if ip_rate_limiter.limit?(user_ip)
			  handle_rate_limited_signup(user_ip, @user_signup.email) && return
			end
	
			# Prevent signups from potential spammers
			if spam_user?(@user_signup)
			  handle_spam_user(@user_signup) do
				render action: 'sign'
			  end && return
			end
	
			@user_signup.email_confirmed = false
			@user_signup.save!
			send_confirmation_mail @user_signup
			return
		  end
		end
	  rescue ActionController::ParameterMissing
		flash[:error] = _('Invalid form submission')
		render action: :sign
	  end
	end

  PublicBodyController.class_eval do
    def list
      long_cache

      @tag = params[:tag] || 'all'
      @locale = AlaveteliLocalization.locale
      
      if @locale == "ka"
        @tag = @tag if @tag.scan(/./mu).size == 1
      else
        @tag = @tag.upcase if @tag.scan(/./mu).size == 1
      end

      @country_code = AlaveteliConfiguration.iso_country_code
      

      AlaveteliLocalization.with_locale(@locale) do
        @public_bodies = PublicBody.visible.
                                  with_tag(@tag).
                                  with_query(params[:public_body_query], @tag).
                                  paginate(page: params[:page], per_page: 100)

        @description =
          if @tag == 'all'
            n_('Found {{count}} public authority',
               'Found {{count}} public authorities',
               @public_bodies.total_entries,
               :count => @public_bodies.total_entries)
          elsif @tag.size == 1
            n_('Found {{count}} public authority beginning with ' \
               '‘{{first_letter}}’',
               'Found {{count}} public authorities beginning with ' \
               '‘{{first_letter}}’',
               @public_bodies.total_entries,
               :count => @public_bodies.total_entries,
               :first_letter => @tag)
          else
            category_name = PublicBodyCategory.get.by_tag[@tag]
            if category_name.nil?
              n_('Found {{count}} public authority matching the tag ' \
               '‘{{tag_name}}’',
               'Found {{count}} public authorities matching the tag ' \
               '‘{{tag_name}}’',
               @public_bodies.total_entries,
               :count => @public_bodies.total_entries,
               :tag_name => @tag)
            else
              n_('Found {{count}} public authority in the category ' \
               '‘{{category_name}}’',
               'Found {{count}} public authorities in the category ' \
               '‘{{category_name}}’',
               @public_bodies.total_entries,
               :count => @public_bodies.total_entries,
               :category_name => category_name)
            end
          end

        respond_to do |format|
          format.html { render :template => 'public_body/list' }
        end
      end
    end

  end
  # Example adding an instance variable to the frontpage controller
  # GeneralController.class_eval do
  #   def mycontroller
  #     @say_something = "Greetings friend"
  #   end
  # end
  # Example adding a new action to an existing controller
  # HelpController.class_eval do
  #   def help_out
  #   end
  # end
end
